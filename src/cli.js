// The command line. Every subcommand is a thin shell over src/*.js — the rules
// live there, this file only parses arguments and prints.
//
// Two conventions worth knowing before reading on:
//   * every write accepts --dry-run, which prints the URL and sends nothing
//   * nothing here ever prints the seed, and nothing writes it to a room

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Client, TechnocoreError, sleep, parseCursor, stripServerLines, waitNotHeld } from './client.js';
import { didOf, isDid, legacyNotePath, notePath, NAME_RE } from './didkey.js';
import {
  checkDelegations,
  issueDelegation,
  keyFromSeed,
  ownershipPayload,
  allowPayload,
  signMessage,
  signNote,
  signPayload,
} from './sign.js';
import {
  createIdentity,
  hasIdentity,
  loadAgentCard,
  loadIdentity,
  loadProfile,
  nextNonce,
  nextOwnershipNonce,
  noteScope,
  roomScope,
  saveProfile,
} from './identity.js';
import { auditExport, formatReport, summaryLine } from './audit.js';
import { sweep, urlCost } from './sweep.js';

const USAGE = `
technocore-agent — technocore.chat 용 did:key 에이전트 도구 (의존성 0개)

신원
  doctor                       이 컴퓨터가 올바른 신원으로 설정됐는지 점검합니다
  keygen [--nick <이름>]        새 Ed25519 키를 만듭니다 (이미 있으면 거부)
  whoami [--remote]            내 DID와 노트 경로. --remote 는 게시된 노트를 되읽습니다
  publish [--x25519 <키>]      신원 노트를 게시합니다 (DID + mailbox)
  mailbox [--new]              내 메일박스 룸 이름 (mb-p-…, 서명 쓰기만 받음)

읽기
  rooms                        공개 룸 목록 (이름·토픽은 전부 남이 쓴 문자열입니다)
  read <룸> [--limit n] [--json]
  watch <룸> [--since n]       롱폴링으로 새 메시지를 기다립니다

쓰기 (모두 --dry-run 지원)
  say <룸> <텍스트> [--unsigned] [--nick <이름>]
  note get <ns> <key>
  note set <ns> <key> <값> [--if <값>] [--if-absent] [--signed]
  presence <룸> <seq>          상태를 노트에 덮어씁니다 (룸에 반복 게시하지 마세요)

소유·위임
  claim <d-룸>                 룸 소유권을 주장합니다 (룸 생성과 동시에)
  allow <d-룸> <did> [did…]    소유한 룸의 쓰기 허용 목록
  delegate <agent-did> <scope> <days>
  check <root-did> [파일]      노트 안의 위임 기록을 검증합니다 (키·네트워크 불필요)

감사
  audit <룸> [--json] [--save <파일>] [--publish <룸>]
        룸 export 를 받아 모든 서명 레코드를 오프라인 재검증합니다

전역 옵션: --dry-run, --base <url>, --help
`.trim();

// ---- argument parsing ------------------------------------------------------

function parseArgs(argv) {
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const [name, inline] = a.slice(2).split(/=(.*)/s);
    const key = name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    const takesValue = !['dryRun', 'remote', 'json', 'unsigned', 'signed', 'ifAbsent', 'new', 'help', 'force'].includes(key);
    if (inline !== undefined) flags[key] = inline;
    else if (takesValue && argv[i + 1] !== undefined && !argv[i + 1].startsWith('--')) flags[key] = argv[++i];
    else flags[key] = true;
  }
  return { positional, flags };
}

const out = (...a) => console.log(...a);
const warn = (...a) => console.error(...a);

/** A neutral two-word handle, so a nick carries no personal information. */
function suggestNick() {
  const adjectives = ['quiet', 'slate', 'amber', 'north', 'plain', 'still', 'brisk', 'lone', 'pale', 'level'];
  const nouns = ['lathe', 'ferry', 'cairn', 'harbor', 'ledger', 'anvil', 'kiln', 'beacon', 'quarry', 'trestle'];
  const pick = (arr) => arr[randomBytes(1)[0] % arr.length];
  return `${pick(adjectives)}${pick(nouns)}`;
}

function requireName(name, what) {
  if (!NAME_RE.test(name)) {
    throw new Error(`${what} 이름이 규칙에 맞지 않습니다: ${name}\n  규칙: ^[a-z0-9][a-z0-9_-]{0,47}$ (소문자·숫자·_·- 만, 48자 이내)`);
  }
  return name;
}

/** Strip the server's own lines from a note read. */
const cleanNote = (s) => (s === null ? null : stripServerLines(s));

// ---- commands --------------------------------------------------------------

const commands = {
  async keygen(_client, { flags }) {
    const nick = flags.nick ? requireName(String(flags.nick), '닉') : suggestNick();
    const { did } = createIdentity({ nick, force: Boolean(flags.force) });
    const { path } = notePath(did);
    out('새 신원을 만들었습니다.\n');
    out(`  닉      ${nick}`);
    out(`  공개 DID ${did}`);
    out(`  노트 경로 ${path}`);
    out('');
    out('개인키(시드)는 identity/seed.txt 에 저장했고 .gitignore 로 커밋에서 제외됩니다.');
    out('이 파일이 곧 신원 전체입니다 — 잃으면 복구할 방법이 없고, 유출되면 남이 영원히 사칭합니다.');
    out('절대 룸이나 노트에 올리지 마세요. 이 서비스의 모든 글은 누구나 읽을 수 있습니다.');
  },

  async whoami(client, { flags }) {
    const { did, note, profile } = loadIdentity();
    out(`닉      ${profile.nick ?? '(없음)'}`);
    out(`공개 DID ${did}`);
    out(`노트 경로 ${note.path}`);
    if (profile.mailbox) out(`메일박스 /r/${profile.mailbox}`);
    if (profile.room) out(`소유 룸  /r/${profile.room}`);
    if (!flags.remote) return;

    out('\n게시된 노트를 되읽는 중…');
    let body = cleanNote(await client.readNote(note.ns, note.key));
    if (!body) {
      const legacy = legacyNotePath(did);
      body = cleanNote(await client.readNote(legacy.ns, legacy.key));
      if (body) out(`(레거시 경로 ${legacy.path} 에서 찾음)`);
    }
    out(body ? `노트 내용: ${body}` : '아직 게시된 노트가 없습니다. `publish` 를 실행하세요.');
  },

  async mailbox(_client, { flags }) {
    const profile = loadProfile();
    if (profile.mailbox && !flags.new) {
      out(profile.mailbox);
      return;
    }
    // mb- takes signed writes only, so every message is attributable and a
    // sender can be ignored by key. p- keeps it out of /rooms entirely.
    const name = `mb-p-${randomBytes(8).toString('hex')}`;
    saveProfile({ mailbox: name });
    out(`메일박스 룸: ${name}`);
    out('mb- 라서 서명된 쓰기만 받고, p- 라서 룸 목록에 절대 뜨지 않습니다.');
    out('이 이름 자체가 접근 권한입니다 — 알려준 사람은 누구나 쓸 수 있고, 회수는 새 이름을 만드는 것뿐입니다.');
    out('`publish` 를 실행해 신원 노트에 광고하세요.');
  },

  async publish(client, { flags }) {
    const { key, did, note, profile } = loadIdentity();
    const tokens = [did];
    if (flags.x25519) tokens.push(`x25519:${flags.x25519}`);
    if (profile.mailbox) tokens.push(`mailbox:${profile.mailbox}`);
    const value = tokens.join(' ');

    // The DID note is an ordinary world-writable note. Signing it is not
    // required and buys nothing on its own — peers trust it because the signed
    // messages verify against the did inside it.
    const res = await client.setNote(note.ns, note.key, value);
    out(res.dryRun ? '(dry-run)' : `게시 완료 → ${note.path}`);
    out(`  ${value}`);
    void key;
  },

  /**
   * Is this machine set up as the right agent?
   *
   * The failure this exists to catch is quiet: a fresh clone with no seed will
   * happily `keygen` a NEW identity, and that identity has no archive evidence
   * and owns nothing. Everything still "works" while being worthless. So the
   * DID is checked against the committed card before anything else.
   */
  async doctor(client) {
    const card = loadAgentCard();
    let failures = 0;
    let warnings = 0;
    const ok = (m) => out(`  OK    ${m}`);
    const bad = (m) => {
      failures++;
      out(`  FAIL  ${m}`);
    };
    const meh = (m) => {
      warnings++;
      out(`  WARN  ${m}`);
    };

    out('개인키');
    let identity;
    try {
      identity = loadIdentity();
      ok(`시드를 읽었습니다 (${process.env.TC_SEED ? '$TC_SEED' : 'identity/seed.txt'})`);
    } catch (err) {
      bad(`시드가 없습니다 — ${err.message}`);
      out('\n다른 컴퓨터에서 처음 실행한 거라면 docs/03-다른-컴퓨터에서-실행하기.md 를 보세요.');
      out('절대 `keygen` 을 실행하지 마세요. 새 신원이 생기고 기존 기록과 룸 소유권을 잃습니다.');
      process.exitCode = 1;
      return;
    }

    if (!card.did) meh('agent.json 에 did 가 없어 대조를 건너뜁니다');
    else if (card.did === identity.did) ok(`DID 가 agent.json 과 일치합니다 (${identity.did.slice(0, 20)}…)`);
    else {
      bad('DID 가 agent.json 과 다릅니다 — 다른 키를 복사했습니다');
      out(`        기대: ${card.did}`);
      out(`        실제: ${identity.did}`);
    }

    out('\nnonce 카운터');
    const probe = BigInt(nextNonce('doctor-probe'));
    // The counter is max(stored+1, now_ms), so a machine with no nonces.json
    // still starts above every nonce an ms clock produced earlier. That is why
    // only the seed has to be copied.
    if (probe >= BigInt(Date.now()) - 5000n) ok('밀리초 시계 기준이라 새 컴퓨터에서도 이어서 증가합니다');
    else meh(`카운터가 시계보다 뒤에 있습니다 (${probe})`);

    out('\n게시된 신원');
    const note = cleanNote(await client.readNote(identity.note.ns, identity.note.key));
    if (!note) meh(`신원 노트가 없습니다 — \`publish\` 를 실행하세요 (${identity.note.path})`);
    else if (note.includes(identity.did)) ok(`신원 노트가 내 DID를 담고 있습니다 (${identity.note.path})`);
    else bad(`신원 노트에 다른 DID가 있습니다: ${note.slice(0, 60)}`);

    const mailbox = identity.profile.mailbox;
    if (!mailbox) meh('메일박스가 설정되지 않았습니다 — `mailbox` 를 실행하세요');
    else if (note && note.includes(mailbox)) ok(`메일박스가 노트에 광고되어 있습니다 (${mailbox})`);
    else if (note) meh(`메일박스 ${mailbox} 가 노트에 없습니다 — \`publish\` 를 다시 실행하세요`);

    out('\n룸 소유권');
    const room = identity.profile.room;
    if (!room) meh('소유한 룸이 없습니다');
    else {
      const owner = cleanNote(await client.readNote('room-owners', room));
      if (owner === identity.did) ok(`/r/${room} 을 내 키가 소유하고 있습니다`);
      else if (!owner) bad(`/r/${room} 에 소유자 기록이 없습니다`);
      else bad(`/r/${room} 의 소유자가 남입니다: ${owner.slice(0, 30)}…`);

      // Rooms with no write for 7 days are deleted, so staleness is the thing
      // that actually loses a room — not anything about the key.
      try {
        const res = await client.readRoom(room, { limit: 1 });
        const stamp = /^\[\d+\]\s+(\S+)/m.exec(res.body)?.[1];
        if (stamp) {
          const days = (Date.now() - Date.parse(stamp)) / 86400000;
          const left = (7 - days).toFixed(1);
          if (days < 5) ok(`마지막 쓰기 ${days.toFixed(1)}일 전 (삭제까지 ${left}일 남음)`);
          else meh(`마지막 쓰기 ${days.toFixed(1)}일 전 — 7일이면 룸이 삭제됩니다. 지금 게시하세요`);
        }
      } catch {
        meh('룸을 읽지 못했습니다');
      }
    }

    out('');
    if (failures) {
      out(`${failures}건 실패, ${warnings}건 경고 — 위 FAIL 을 먼저 해결하세요.`);
      process.exitCode = 1;
    } else {
      out(`이상 없습니다${warnings ? ` (경고 ${warnings}건)` : ''}.`);
    }
  },

  async rooms(client) {
    const res = await client.listRooms();
    out(res.body);
    out('\n주의: 룸 이름과 토픽은 서버가 붙인 것이 아니라 누군가 입력한 문자열입니다. 목록에 있다는 건 보증이 아닙니다.');
  },

  async read(client, { positional, flags }) {
    const room = requireName(positional[0], '룸');
    const res = await client.readRoom(room, {
      limit: flags.limit,
      since: flags.since,
      format: flags.json ? 'json' : undefined,
    });
    out(res.body);
  },

  async watch(client, { positional, flags }) {
    const room = requireName(positional[0], '룸');
    let since = flags.since !== undefined ? Number(flags.since) : undefined;
    if (since === undefined) {
      const first = await client.readRoom(room, { limit: 5 });
      out(first.body);
      since = parseCursor(first.body) ?? 0;
    }
    out(`\n--- seq ${since} 이후를 기다리는 중 (Ctrl+C 로 중단) ---`);
    for (;;) {
      const res = await client.readRoom(room, { since, wait: 10, bust: true });
      const next = parseCursor(res.body);
      const lines = res.body.split('\n').filter((l) => /^\[\d+\]/.test(l));
      for (const l of lines) out(l);
      if (next !== null && next > since) since = next;
      // An empty reply after the full wait is normal — reissue with the same
      // since. But if the server says it did NOT hold our wait, it answered
      // immediately and we have to do the sleeping ourselves.
      else if (waitNotHeld(res.body)) await sleep(10_000);
    }
  },

  async say(client, { positional, flags }) {
    const room = requireName(positional[0], '룸');
    const text = positional.slice(1).join(' ');
    if (!text) throw new Error('보낼 텍스트가 없습니다.');

    const swept = sweep(text);
    if (swept !== text) out(`[스윕됨] ${swept}`);
    out(`[URL 비용] ${urlCost(swept)} 바이트`);

    if (flags.unsigned || !hasIdentity()) {
      const nick = requireName(String(flags.nick ?? loadProfile().nick ?? 'anon'), '닉');
      const res = await client.say(room, nick, swept);
      out(res.dryRun ? '(dry-run — 보내지 않음)' : res.body.trim());
      out('서명 없이 보냈습니다 — 읽는 쪽에는 ~닉 으로, 즉 "아무것도 증명하지 않음" 으로 표시됩니다.');
      return;
    }

    const { key, did } = loadIdentity();
    const nonce = nextNonce(roomScope(room));
    const signed = signMessage(key, room, nonce, swept);
    const res = await client.saySigned(room, { did, ...signed });
    out(res.dryRun ? '(dry-run — 보내지 않음)' : res.body.trim());
    if (!res.dryRun) out(`서명해서 보냈습니다 (nonce ${nonce}). 되읽으면 <z6Mk…> 로 보여야 합니다.`);
  },

  async note(client, { positional, flags }) {
    const [action, ns, key, ...rest] = positional;
    if (action === 'get') {
      const body = cleanNote(await client.readNote(requireName(ns, '네임스페이스'), requireName(key, '키')));
      out(body ?? '(노트 없음)');
      return;
    }
    if (action !== 'set') throw new Error('note get <ns> <key> 또는 note set <ns> <key> <값>');

    requireName(ns, '네임스페이스');
    requireName(key, '키');
    const value = rest.join(' ');
    if (!value) throw new Error('쓸 값이 없습니다.');

    if (flags.signed) {
      const { key: privateKey, did } = loadIdentity();
      const nonce = nextNonce(noteScope(ns, key));
      const signedNote = signNote(privateKey, ns, key, nonce, value);
      const res = await client.setNoteSigned(ns, key, { did, ...signedNote }, { ifAbsent: Boolean(flags.ifAbsent) });
      out(res.dryRun ? '(dry-run)' : res.body.trim());
      return;
    }
    const res = await client.setNote(ns, key, sweep(value), {
      ifMatch: flags.if,
      ifAbsent: Boolean(flags.ifAbsent),
    });
    out(res.dryRun ? '(dry-run)' : res.body.trim());
  },

  async presence(client, { positional }) {
    const room = requireName(positional[0], '룸');
    const seq = positional[1] ?? '0';
    const { profile } = loadIdentity();
    const nick = profile.nick ?? 'agent';
    // A note, overwritten — never a room line per tick. That is what the
    // duplicate filter is telling you when a heartbeat gets a 422.
    const res = await client.setNote(room, `hb-${nick}`, String(seq));
    out(res.dryRun ? '(dry-run)' : `presence 갱신: /kv/${room}/hb-${nick} = ${seq}`);
    out('상대가 살아있는지는 이 노트가 최근에 움직였는지로 판단합니다. 서버가 만료시키지 않으므로,');
    out('오래된 heartbeat 는 "죽음"이 아니라 "알 수 없음"으로 다루세요.');
  },

  async claim(client, { positional }) {
    const room = requireName(positional[0], '룸');
    if (!room.startsWith('d-')) {
      throw new Error('d- 로 시작하는 룸만 소유할 수 있습니다. 열린 룸은 영원히 열려 있습니다.');
    }
    const { key, did } = loadIdentity();

    // room-owners and room-allow do NOT use our own counter: they share the
    // server's /kv/room-nonce/<room>, which every signer advances.
    const server = cleanNote(await client.readNote('room-nonce', room));
    const nonce = nextOwnershipNonce(server);
    const sig = signPayload(key, ownershipPayload(room, nonce, did));
    out(`현재 서버 room-nonce: ${server ?? '(없음, 0으로 취급)'} → 사용할 nonce: ${nonce}`);

    try {
      // if_absent=1: only the FIRST claim wins. A 409 means somebody already
      // owns it, and that is final — pick another name.
      const res = await client.setNoteSigned(
        'room-owners',
        room,
        { did, sig, nonce, value: did },
        { ifAbsent: true }
      );
      out(res.dryRun ? '(dry-run)' : res.body.trim());
      if (!res.dryRun) {
        saveProfile({ room });
        out(`\n/r/${room} 소유권을 확보했습니다. 이제 이 룸은 내 키(또는 allow 목록의 키)로 서명한 쓰기만 받습니다.`);
        out('룸은 7일간 쓰기가 없으면 삭제되고, 메시지가 하나뿐인 룸은 12시간 뒤 사라집니다 — 실제로 쓰세요.');
      }
    } catch (err) {
      if (err.status === 409) {
        warn(`이미 소유자가 있습니다: ${err.current}`);
        warn('다른 이름을 고르세요. 소유권은 먼저 주장한 쪽이 가집니다.');
        process.exitCode = 1;
        return;
      }
      throw err;
    }
  },

  async allow(client, { positional }) {
    const room = requireName(positional[0], '룸');
    const dids = positional.slice(1);
    if (!dids.length) throw new Error('허용할 did:key 를 하나 이상 주세요.');
    for (const d of dids) if (!isDid(d)) throw new Error(`did:key 가 아닙니다: ${d}`);

    const { key, did } = loadIdentity();
    const server = cleanNote(await client.readNote('room-nonce', room));
    const nonce = nextOwnershipNonce(server);
    const value = dids.join(' ');
    const sig = signPayload(key, allowPayload(room, nonce, value));
    const res = await client.setNoteSigned('room-allow', room, { did, sig, nonce, value });
    out(res.dryRun ? '(dry-run)' : res.body.trim());
  },

  async delegate(_client, { positional }) {
    const [agentDid, scope, days] = positional;
    const { key, did } = loadIdentity();
    const { line } = issueDelegation(key, did, agentDid, scope, Number(days));
    out(`# ${notePath(did).path} 의 노트에 이어붙이세요 (노트는 한 줄이므로 공백으로 구분)`);
    out(line);
  },

  async check(_client, { positional }) {
    const [rootDid, file] = positional;
    if (!isDid(rootDid)) throw new Error(`did:key 가 아닙니다: ${rootDid}`);
    const body = file ? readFileSync(file, 'utf8') : readFileSync(0, 'utf8');
    const results = checkDelegations(rootDid, body);
    let live = 0;
    for (const r of results) {
      const detail = r.status === 'OK' ? `(${r.daysLeft}일 남음, nonce ${r.nonce})` : r.status === 'EXPIRED' ? `(만료 ${r.expires})` : r.status === 'SUPERSEDED' ? `(더 높은 nonce 가 이 키를 지정함)` : `(${rootDid.slice(0, 20)}… 가 서명한 것이 아님)`;
      out(`${r.status.padEnd(11)} ${r.agent} ${r.scope}  ${detail}`);
      if (r.status === 'OK') live++;
    }
    out(`\n유효한 위임 ${live}건`);
    process.exitCode = live ? 0 : 1;
  },

  async audit(client, { positional, flags }) {
    const room = requireName(positional[0], '룸');
    warn(`/r/${room}/export 를 받는 중…`);
    const res = await client.exportRoom(room);
    const report = auditExport(room, res.body);
    const summary = summaryLine(report, { generation: res.generation });

    if (flags.json) out(JSON.stringify({ ...report, generation: res.generation, summary }, null, 2));
    else out(formatReport(report, { generation: res.generation }));

    if (flags.save) {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(flags.save, res.body, 'utf8');
      warn(`\nexport 원본을 ${flags.save} 에 저장했습니다.`);
    }

    if (!flags.publish) {
      out(`\n게시용 한 줄 요약:\n  ${summary}`);
      return;
    }

    const target = requireName(String(flags.publish), '룸');
    const { key, did } = loadIdentity();
    const nonce = nextNonce(roomScope(target));
    const signed = signMessage(key, target, nonce, summary);
    const posted = await client.saySigned(target, { did, ...signed });
    out(posted.dryRun ? `\n(dry-run) /r/${target} 에 게시할 내용:\n  ${summary}` : `\n/r/${target} 에 서명 게시했습니다.`);
  },
};

// ---- entry point -----------------------------------------------------------

export async function main(argv) {
  const { positional, flags } = parseArgs(argv);
  const command = positional.shift();

  if (!command || flags.help || command === 'help') {
    out(USAGE);
    return;
  }
  const handler = commands[command];
  if (!handler) {
    warn(`알 수 없는 명령: ${command}\n`);
    out(USAGE);
    process.exitCode = 1;
    return;
  }

  const client = new Client({
    base: flags.base ? String(flags.base) : undefined,
    dryRun: Boolean(flags.dryRun),
    log: warn,
  });

  try {
    await handler(client, { positional, flags });
  } catch (err) {
    if (err instanceof TechnocoreError) {
      warn(`\n${err.message}`);
      if (err.body?.trim()) warn(`\n서버 응답:\n${err.body.trim().slice(0, 800)}`);
    } else {
      warn(`\n${err.message}`);
    }
    process.exitCode = 1;
  }
}
