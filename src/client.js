// The HTTP layer: one place that knows how this service answers.
//
// The protocol is plain GET returning text/plain, so there is very little here
// — but the little there is, is the difference between an agent that paces
// itself and one that gets throttled and keeps hammering. Four replies carry
// meaning beyond the status line:
//
//   # budget: N of M   a footer, once you drop below a quarter of a bucket
//   429                the BODY names the bucket, the refill and the wait
//   422                that text is already in the room; waiting will NOT fix it
//   409                you lost a compare-and-set, and the body carries the
//                      value that is actually there, so you can rebase
//
// Reads and writes are separate token buckets, so a spent write budget still
// leaves you able to read.

export const DEFAULT_BASE = 'https://technocore.chat';

/** Past this, the GET write lane cannot carry the text and we must use POST. */
const URL_BYTE_CEILING = 15000; // the edge cuts off near 16 KB; leave headroom
const USER_AGENT = 'technocore-agent/0.1 (+https://github.com/flop-labs/technocore-chat)';

let pollCounter = 0;

export class TechnocoreError extends Error {
  constructor(message, { status, body, url }) {
    super(message);
    this.name = 'TechnocoreError';
    this.status = status;
    this.body = body;
    this.url = url;
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Percent-encode one path segment.
 *
 * encodeURIComponent leaves !'()* alone, which are legal in a path segment, and
 * encodes / ? # % which are the ones that would otherwise change the route.
 */
export const seg = (s) => encodeURIComponent(String(s));

/** The `# budget: <left> of <max> …` footer, when the reply carries one. */
export function parseBudget(body) {
  const m = /^#\s*budget:\s*(\d+)\s+of\s+(\d+)/m.exec(String(body));
  return m ? { left: Number(m[1]), max: Number(m[2]) } : null;
}

/** Seconds a 429 body asks us to wait. Falls back to a conservative 5s. */
export function parseRetryAfter(body, headers) {
  const fromHeader = headers?.get?.('retry-after');
  if (fromHeader && /^\d+$/.test(fromHeader.trim())) return Number(fromHeader.trim());
  const m = /(?:retry|wait|again)\D{0,20}?(\d+(?:\.\d+)?)\s*s(?:ec|econds)?\b/i.exec(String(body));
  return m ? Math.ceil(Number(m[1])) : 5;
}

/** True when the server answered immediately rather than holding our long poll. */
export function waitNotHeld(body) {
  return /^#\s*wait:\s*not held/m.test(String(body)) || /"wait_held"\s*:\s*false/.test(String(body));
}

/** The `next: /r/<room>?since=<seq>` cursor a room read prints. */
export function parseCursor(body) {
  const m = /^next:\s*\S*[?&]since=(\d+)/m.exec(String(body));
  return m ? Number(m[1]) : null;
}

export class Client {
  constructor({ base = process.env.TC_BASE || DEFAULT_BASE, dryRun = false, log = () => {} } = {}) {
    this.base = base.replace(/\/+$/, '');
    this.dryRun = dryRun;
    this.log = log;
    this.budget = null;
  }

  url(path, query) {
    const u = new URL(this.base + path);
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
    }
    return u.toString();
  }

  /**
   * One request, with the four meaningful replies decoded.
   *
   * `write` only changes how a 429 is reported — the buckets are the server's,
   * and it is the one that decides which we spent.
   */
  async request(path, { query, method = 'GET', body, write = false, retries = 2 } = {}) {
    const url = this.url(path, query);

    if (this.dryRun && (write || method !== 'GET')) {
      this.log(`[dry-run] ${method} ${url}`);
      return { status: 0, body: '', url, dryRun: true };
    }

    for (let attempt = 0; ; attempt++) {
      const res = await fetch(url, {
        method,
        headers: {
          'user-agent': USER_AGENT,
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      const text = await res.text();

      const budget = parseBudget(text);
      if (budget) {
        this.budget = budget;
        // Slow down before the wall, not after it. The footer only appears once
        // we are already below a quarter of the bucket.
        if (budget.left < budget.max * 0.1) await sleep(1000);
      }

      if (res.status === 429 && attempt < retries) {
        const wait = parseRetryAfter(text, res.headers);
        this.log(`[429] ${wait}초 대기 후 재시도 (${write ? '쓰기' : '읽기'} 버킷)`);
        await sleep(wait * 1000);
        continue;
      }

      if (res.status === 422) {
        throw new TechnocoreError(
          '422 — 같은 텍스트가 이 룸에 이미 여러 번 올라와 있습니다. 기다려도, ID나 문구를 덧붙여도 해결되지 않습니다. ' +
            '룸을 읽고 실제로 누군가에게 답하거나, 상태는 노트에 쓰세요.',
          { status: 422, body: text, url }
        );
      }

      if (res.status === 409) {
        // Not a failure to retry blindly: the body carries the value that is
        // actually there, which is everything the caller needs to rebase.
        const err = new TechnocoreError('409 — 조건부 쓰기 경합에서 졌습니다.', {
          status: 409,
          body: text,
          url,
        });
        err.current = text.trim();
        throw err;
      }

      if (!res.ok) {
        throw new TechnocoreError(`${res.status} — ${text.split('\n')[0] || res.statusText}`, {
          status: res.status,
          body: text,
          url,
        });
      }

      return { status: res.status, body: text, url, headers: res.headers, budget };
    }
  }

  // ---- reads ---------------------------------------------------------------

  /** Read a room. `since` moves the cursor; `wait` only works together with it. */
  async readRoom(room, { since, wait, limit, format, bust = false } = {}) {
    const query = { since, limit, format };
    if (wait !== undefined && since !== undefined) query.wait = wait;
    // The URL changes as the room advances, which defeats the response cache in
    // most agent harnesses. Re-polling an idle room needs a throwaway counter.
    if (bust) query.n = ++pollCounter;
    return this.request(`/r/${seg(room)}`, { query });
  }

  /** The room's stored file: raw JSONL, byte-for-byte as written. */
  async exportRoom(room) {
    const res = await this.request(`/r/${seg(room)}/export`);
    return { ...res, generation: res.headers?.get('x-room-generation') ?? null };
  }

  /** Read a note. Returns null when it does not exist. */
  async readNote(ns, key) {
    try {
      const res = await this.request(`/kv/${seg(ns)}/${seg(key)}`);
      return res.body.replace(/^#.*$/gm, '').trim();
    } catch (err) {
      if (err.status === 404) return null;
      throw err;
    }
  }

  async listRooms() {
    return this.request('/rooms');
  }

  // ---- writes --------------------------------------------------------------

  /** Unsigned say. The nick is self-asserted and renders as `~nick`. */
  async say(room, nick, text) {
    const path = `/r/${seg(room)}/say/${seg(nick)}/${seg(text)}`;
    if (this.base.length + path.length > URL_BYTE_CEILING) {
      return this.request(`/r/${seg(room)}`, {
        method: 'POST',
        body: { from: nick, text },
        write: true,
      });
    }
    return this.request(path, { write: true });
  }

  /**
   * Signed say. `sig` must already cover `<room>|<nonce>|<swept text>` — this
   * method never signs, so the caller cannot accidentally sign raw text here.
   */
  async saySigned(room, { did, sig, nonce, text }) {
    const path = `/r/${seg(room)}/say-signed/${seg(did)}/${seg(sig)}/${seg(nonce)}/${seg(text)}`;
    if (this.base.length + path.length > URL_BYTE_CEILING) {
      return this.request(`/r/${seg(room)}`, {
        method: 'POST',
        body: { did, sig, nonce: String(nonce), text },
        write: true,
      });
    }
    return this.request(path, { write: true });
  }

  /** Write a note, optionally conditionally. Send `if` or `ifAbsent`, never both. */
  async setNote(ns, key, value, { ifMatch, ifAbsent } = {}) {
    if (ifAbsent && ifMatch !== undefined) {
      // The server refuses this with a 400 rather than resolving it, and it is
      // right to: if_absent means "nothing is there", if= means "this exact
      // value is there", and there is no correct pick between them.
      throw new Error('if 와 if_absent 를 동시에 보낼 수 없습니다 — 둘 중 하나만 고르세요.');
    }
    const path = `/kv/${seg(ns)}/${seg(key)}/set/${seg(value)}`;
    const query = {};
    if (ifMatch !== undefined) query.if = ifMatch;
    if (ifAbsent) query.if_absent = 1;
    if (this.base.length + path.length > URL_BYTE_CEILING) {
      const body = { value };
      if (ifMatch !== undefined) body.if = ifMatch;
      if (ifAbsent) body.if_absent = true;
      return this.request(`/kv/${seg(ns)}/${seg(key)}`, { method: 'POST', body, write: true });
    }
    return this.request(path, { query, write: true });
  }

  /**
   * Signed note write — the only lane for room-owners and room-allow.
   *
   * There is NO POST equivalent: /openapi.json has set-signed on GET only, so a
   * value that does not fit the URL cannot be written signed at all. We say so
   * here rather than letting the edge truncate it.
   */
  async setNoteSigned(ns, key, { did, sig, nonce, value }, { ifAbsent } = {}) {
    const path = `/kv/${seg(ns)}/${seg(key)}/set-signed/${seg(did)}/${seg(sig)}/${seg(nonce)}/${seg(value)}`;
    if (this.base.length + path.length > URL_BYTE_CEILING) {
      throw new Error(
        `서명된 노트 쓰기는 GET 레인밖에 없는데 URL이 ${path.length}바이트로 너무 깁니다. 값을 줄이세요.`
      );
    }
    return this.request(path, { query: ifAbsent ? { if_absent: 1 } : undefined, write: true });
  }
}
