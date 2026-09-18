// The auditor: re-verify a room's signed records offline, from its export.
//
// The manual makes byte-exactness of /r/<room>/export a design goal precisely so
// that "a signed record re-verifies from its exported line alone". This is the
// thing that actually does it.
//
// Two traps, both of which silently produce wrong answers:
//
//  1. A stored nonce may be up to 19 digits, which is past 2^53. JSON.parse
//     rounds it to a float and a rounded nonce fails a GOOD signature. The raw
//     ASCII digits have to come out of the line before any JSON number parsing.
//
//  2. `text` is a JSON string that can itself contain `"nonce": …` — tclk frames
//     in the wild do exactly that. So the digits cannot be grabbed with a naive
//     regex over the line; the field has to be located at the top level, outside
//     any string literal.
//
// A record with no `sig` is NOT invalid. Records written before `sig` existed do
// not have the field, and the manual is explicit: treat a missing `sig` as
// "not re-verifiable", never as "forged".

import { messagePayload, verifyPayload } from './sign.js';
import { isDid } from './didkey.js';

/**
 * The raw source text of every top-level field in one JSON object line.
 *
 * Walks the line tracking string state and nesting depth, so a key that appears
 * inside `text` is never mistaken for the record's own. Returns a Map of key ->
 * the untouched source slice of its value.
 */
export function rawTopLevelFields(line) {
  const out = new Map();
  let i = 0;
  let depth = 0;
  let inString = false;
  let escaped = false;
  let pendingKey = null;
  let valueStart = -1;

  const readStringAt = (start) => {
    // Returns [decoded, indexAfterClosingQuote] for a JSON string beginning at `start`.
    let j = start + 1;
    let esc = false;
    for (; j < line.length; j++) {
      const c = line[j];
      if (esc) {
        esc = false;
        continue;
      }
      if (c === '\\') {
        esc = true;
        continue;
      }
      if (c === '"') break;
    }
    return [line.slice(start, j + 1), j + 1];
  };

  while (i < line.length) {
    const c = line[i];

    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
      i++;
      continue;
    }

    if (c === '"') {
      if (depth === 1 && pendingKey === null && valueStart === -1) {
        // A key at the top level. Read it whole rather than character by
        // character so the scanner cannot be desynchronised by an escape.
        const [raw, after] = readStringAt(i);
        pendingKey = JSON.parse(raw);
        i = after;
        continue;
      }
      inString = true;
      i++;
      continue;
    }

    if (c === '{' || c === '[') {
      depth++;
      i++;
      continue;
    }

    if (c === '}' || c === ']') {
      if (depth === 1 && pendingKey !== null && valueStart !== -1) {
        out.set(pendingKey, line.slice(valueStart, i).trim());
        pendingKey = null;
        valueStart = -1;
      }
      depth--;
      i++;
      continue;
    }

    if (c === ':' && depth === 1 && pendingKey !== null && valueStart === -1) {
      valueStart = i + 1;
      i++;
      continue;
    }

    if (c === ',' && depth === 1 && pendingKey !== null && valueStart !== -1) {
      out.set(pendingKey, line.slice(valueStart, i).trim());
      pendingKey = null;
      valueStart = -1;
      i++;
      continue;
    }

    i++;
  }
  return out;
}

/** The record's nonce as the ASCII digits on disk, or null if it is not one. */
export function rawNonce(line) {
  const raw = rawTopLevelFields(line).get('nonce');
  if (raw === undefined) return null;
  const digits = raw.replace(/^"|"$/g, '');
  return /^[0-9]{1,19}$/.test(digits) ? digits : null;
}

/** Verdict for one exported line. */
export function auditLine(room, line) {
  let record;
  try {
    record = JSON.parse(line);
  } catch {
    return { status: 'UNPARSEABLE', line };
  }
  const base = { seq: record.seq, ts: record.ts, from: record.from, text: record.text };

  // An unsigned writer's `from` is a self-asserted nickname, not a DID.
  if (!record.sig) {
    return { ...base, status: isDid(record.from) ? 'NO_SIG' : 'UNSIGNED' };
  }
  if (!isDid(record.from)) {
    return { ...base, status: 'BAD_DID' };
  }

  const nonce = rawNonce(line);
  if (nonce === null) return { ...base, status: 'BAD_NONCE' };

  const ok = verifyPayload(record.from, record.sig, messagePayload(room, nonce, record.text));
  return { ...base, nonce, sig: record.sig, status: ok ? 'VERIFIED' : 'FAILED' };
}

/**
 * Audit a whole export.
 *
 * `nonceRegressions` counts records where a key's nonce did not exceed its own
 * previous one in this room. That is reported, not judged: the server only scans
 * the newest ~1 MiB of a room for the last nonce, so a key writing into a room
 * that has since moved on can legitimately re-use a lower value further back.
 * A cluster of them in recent traffic is the interesting case.
 */
export function auditExport(room, body) {
  const lines = String(body).split('\n').filter((l) => l.trim());
  const counts = {
    total: 0,
    verified: 0,
    failed: 0,
    noSig: 0,
    unsigned: 0,
    badDid: 0,
    badNonce: 0,
    unparseable: 0,
  };
  const keys = new Map(); // did -> { count, lastNonce }
  const failures = [];
  let nonceRegressions = 0;
  let firstSeq = null;
  let lastSeq = null;

  for (const line of lines) {
    const verdict = auditLine(room, line);
    counts.total++;

    if (verdict.seq !== undefined) {
      if (firstSeq === null || verdict.seq < firstSeq) firstSeq = verdict.seq;
      if (lastSeq === null || verdict.seq > lastSeq) lastSeq = verdict.seq;
    }

    switch (verdict.status) {
      case 'VERIFIED':
        counts.verified++;
        break;
      case 'FAILED':
        counts.failed++;
        failures.push(verdict);
        break;
      case 'NO_SIG':
        counts.noSig++;
        break;
      case 'UNSIGNED':
        counts.unsigned++;
        break;
      case 'BAD_DID':
        counts.badDid++;
        failures.push(verdict);
        break;
      case 'BAD_NONCE':
        counts.badNonce++;
        failures.push(verdict);
        break;
      default:
        counts.unparseable++;
    }

    if (verdict.status === 'VERIFIED' || verdict.status === 'FAILED') {
      const seen = keys.get(verdict.from) ?? { count: 0, lastNonce: null };
      seen.count++;
      if (verdict.nonce) {
        const n = BigInt(verdict.nonce);
        if (seen.lastNonce !== null && n <= seen.lastNonce) nonceRegressions++;
        seen.lastNonce = n;
      }
      keys.set(verdict.from, seen);
    }
  }

  return {
    room,
    counts,
    distinctKeys: keys.size,
    nonceRegressions,
    firstSeq,
    lastSeq,
    failures: failures.slice(0, 20),
    topKeys: [...keys.entries()]
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5)
      .map(([did, v]) => ({ did, count: v.count })),
  };
}

/**
 * A one-line, signable summary of a report.
 *
 * Deliberately says only what this tool actually checked. "verified" means the
 * signature matches the bytes stored — not that the writer is honest, and not
 * that anything they wrote is true.
 */
export function summaryLine(report, { generation } = {}) {
  const c = report.counts;
  const signed = c.verified + c.failed;
  const parts = [
    `audit /r/${report.room}`,
    `records=${c.total}`,
    `signed=${signed}`,
    `verified=${c.verified}`,
    `failed=${c.failed}`,
    `unsigned=${c.unsigned + c.noSig}`,
    `keys=${report.distinctKeys}`,
  ];
  if (report.firstSeq !== null) parts.push(`seq=${report.firstSeq}-${report.lastSeq}`);
  if (generation) parts.push(`gen=${generation}`);
  if (report.nonceRegressions) parts.push(`nonce-regressions=${report.nonceRegressions}`);
  parts.push('method=offline-ed25519-over-room|nonce|text');
  return parts.join(' ');
}

/** The human-facing report. */
export function formatReport(report, { generation } = {}) {
  const c = report.counts;
  const signed = c.verified + c.failed;
  const pct = signed ? ((c.verified / signed) * 100).toFixed(1) : '0.0';
  const lines = [
    `룸: /r/${report.room}${generation ? `  (generation ${generation})` : ''}`,
    `범위: seq ${report.firstSeq ?? '-'} … ${report.lastSeq ?? '-'}  (보존된 링 전체)`,
    '',
    `총 레코드      ${c.total}`,
    `  서명됨       ${signed}`,
    `    검증 통과  ${c.verified}   (${pct}%)`,
    `    검증 실패  ${c.failed}`,
    `  서명 없음    ${c.unsigned}   (~nick, 자칭 닉네임)`,
    `  sig 필드 없음 ${c.noSig}   (재검증 불가 — 무효라는 뜻이 아님)`,
  ];
  if (c.badDid) lines.push(`  did 파싱 실패 ${c.badDid}`);
  if (c.badNonce) lines.push(`  nonce 이상   ${c.badNonce}`);
  if (c.unparseable) lines.push(`  JSON 파싱 실패 ${c.unparseable}`);
  lines.push('', `고유 서명 키   ${report.distinctKeys}`);
  if (report.nonceRegressions) {
    lines.push(
      `nonce 역행     ${report.nonceRegressions}  (서버는 최신 1MiB만 스캔하므로 오래된 구간에서는 정상일 수 있음)`
    );
  }
  if (report.topKeys.length) {
    lines.push('', '가장 많이 쓴 키:');
    for (const k of report.topKeys) lines.push(`  ${k.count.toString().padStart(6)}  ${k.did}`);
  }
  if (report.failures.length) {
    lines.push('', `검증 실패 샘플 (최대 20건):`);
    for (const f of report.failures) {
      lines.push(`  seq ${f.seq} ${f.status} ${String(f.from).slice(0, 24)}… ${String(f.text).slice(0, 60)}`);
    }
  }
  return lines.join('\n');
}
