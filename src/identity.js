// Local identity: the seed on disk, and the nonce counters that keep the signed
// lane usable across sessions.
//
// Everything in `identity/` is gitignored. The seed is the whole identity —
// there is no recovery, no resolver and no issuer to ask, so a lost seed is a
// lost DID and a leaked seed is somebody else wearing it forever.

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { didOf, generateSeed, notePath } from './didkey.js';
import { keyFromSeed, NONCE_RE } from './sign.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const IDENTITY_DIR = join(ROOT, 'identity');
const SEED_FILE = join(IDENTITY_DIR, 'seed.txt');
const NONCE_FILE = join(IDENTITY_DIR, 'nonces.json');
const PROFILE_FILE = join(IDENTITY_DIR, 'profile.json');
/** Committed, public — see agent.json's own _comment. */
const AGENT_CARD = join(ROOT, 'agent.json');

function readJson(file, fallback) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, value) {
  mkdirSync(IDENTITY_DIR, { recursive: true });
  writeFileSync(file, JSON.stringify(value, null, 2) + '\n', 'utf8');
}

/** True if an identity already exists here. */
export function hasIdentity() {
  return existsSync(SEED_FILE) || Boolean(process.env.TC_SEED);
}

/**
 * Create and persist a new identity. Refuses to overwrite an existing seed:
 * overwriting one silently retires a DID that may already own a room and hold
 * a published note, and nothing can bring it back.
 */
export function createIdentity({ nick, force = false } = {}) {
  if (existsSync(SEED_FILE) && !force) {
    throw new Error(
      `이미 신원이 있습니다: ${SEED_FILE}\n` +
        '덮어쓰면 기존 DID는 영원히 사라집니다. 정말 새로 만들려면 그 파일을 직접 옮기세요.'
    );
  }
  const seed = generateSeed();
  mkdirSync(IDENTITY_DIR, { recursive: true });
  writeFileSync(SEED_FILE, seed + '\n', 'utf8');
  try {
    chmodSync(SEED_FILE, 0o600); // best effort; Windows ACLs do not map onto this
  } catch {
    /* ignore */
  }
  const did = didOf(keyFromSeed(seed));
  const profile = { nick: nick ?? null, did, createdAt: new Date().toISOString() };
  writeJson(PROFILE_FILE, profile);
  return { seed, did, profile };
}

/** The seed, from $TC_SEED if set, else identity/seed.txt. */
export function loadSeed() {
  const fromEnv = process.env.TC_SEED;
  if (fromEnv) return fromEnv.trim();
  if (!existsSync(SEED_FILE)) {
    throw new Error('신원이 없습니다. 먼저 `node bin/tc.js keygen` 을 실행하세요.');
  }
  return readFileSync(SEED_FILE, 'utf8').trim();
}

/** The loaded identity: private key, did, note path, and the local profile. */
export function loadIdentity() {
  const key = keyFromSeed(loadSeed());
  const did = didOf(key);
  return { key, did, note: notePath(did), profile: loadProfile() };
}

/**
 * The local profile, with the committed agent.json as its defaults.
 *
 * identity/ is gitignored, so a fresh clone on another machine has the seed
 * (copied by hand) and nothing else — no nick, and no mailbox name, which is
 * random and NOT derivable from the key. agent.json carries those public facts
 * in the repo so the clone comes up as the same agent rather than a nameless
 * one that mints a second mailbox.
 */
export function loadProfile() {
  const card = readJson(AGENT_CARD, {});
  const local = readJson(PROFILE_FILE, {});
  const { nick, did, mailbox, room } = card;
  return { ...pruneUndefined({ nick, did, mailbox, room }), ...local };
}

/** The committed identity card — public facts, never a secret. */
export function loadAgentCard() {
  return readJson(AGENT_CARD, {});
}

function pruneUndefined(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined));
}

export function saveProfile(patch) {
  const next = { ...loadProfile(), ...patch };
  writeJson(PROFILE_FILE, next);
  return next;
}

/**
 * The next nonce for a scope, persisted.
 *
 * A nonce must be greater than the last one THAT KEY used in that room (and,
 * for the two signed note namespaces, greater than the server's shared
 * /kv/room-nonce/<room> counter — see nextOwnershipNonce, which is a different
 * problem and reads the server's value first).
 *
 * `max(stored + 1, now_ms)` combines a millisecond clock with a strict counter:
 * the clock keeps nonces moving forward across machines that share a seed, and
 * the counter keeps two writes inside the same millisecond apart. A nonce is
 * consumed on issue, not on success — a burnt nonce costs nothing, a reused one
 * is a 403.
 */
export function nextNonce(scope) {
  const counters = readJson(NONCE_FILE, {});
  const previous = BigInt(counters[scope] ?? 0);
  const now = BigInt(Date.now());
  const next = previous + 1n > now ? previous + 1n : now;
  // 19 digits is the server's ceiling; a ms clock reaches 13 and will not cross
  // it this millennium, but a corrupted counter must not produce an unsendable
  // nonce quietly.
  if (String(next).length > 19) throw new Error(`nonce 카운터가 19자리를 넘었습니다 (${scope})`);
  counters[scope] = String(next);
  writeJson(NONCE_FILE, counters);
  return String(next);
}

export function roomScope(room) {
  return `r:${room}`;
}

export function noteScope(ns, key) {
  return `kv:${ns}/${key}`;
}

/**
 * The nonce for a signed write to room-owners / room-allow.
 *
 * Those two namespaces do NOT use a per-key counter: they share the server's
 * /kv/room-nonce/<room>, which every signer advances. So the value has to come
 * from the server, not from our own file. `serverValue` is whatever
 * /kv/room-nonce/<room> currently reads (absent counts as 0).
 */
export function nextOwnershipNonce(serverValue) {
  const raw = String(serverValue ?? '').trim();
  const current = NONCE_RE.test(raw) ? BigInt(raw) : 0n;
  const now = BigInt(Date.now());
  const next = current + 1n > now ? current + 1n : now;
  return String(next);
}
