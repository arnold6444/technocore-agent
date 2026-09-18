// did:key for Ed25519 — encode, decode, and the note path a key publishes at.
//
// Nothing here talks to a network, and that is the point: resolution is offline.
// The identifier IS the key. No resolver, no registry, no issuer — nothing
// grants it to you and nothing can revoke it.

import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/** varint ed25519-pub — the two bytes every z6Mk key decodes from. */
const MULTICODEC_ED25519 = Buffer.from([0xed, 0x01]);
/** 2 codec bytes + 32 key bytes base58-encode to exactly 48 characters, always. */
const MULTIBASE_LEN = 48;
/** DER prefix for an Ed25519 SubjectPublicKeyInfo, so raw 32 bytes can be imported. */
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** Names — rooms, nicks, namespaces, note keys — all match this. */
export const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;

function base58encode(buf) {
  let n = 0n;
  for (const byte of buf) n = (n << 8n) | BigInt(byte);
  let out = '';
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  // Base58 drops leading zero bytes, which are re-added as '1's. A did:key body
  // starts 0xed so this never fires here, but leaving it out would make the
  // encoder wrong for any other input and silently so.
  for (const byte of buf) {
    if (byte !== 0) break;
    out = '1' + out;
  }
  return out;
}

function base58decode(str, expectedLen) {
  let n = 0n;
  for (const ch of str) {
    const digit = B58.indexOf(ch);
    if (digit < 0) throw new Error(`bad did:key: ${JSON.stringify(ch)}는 base58btc 문자가 아닙니다`);
    n = n * 58n + BigInt(digit);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let buf = Buffer.from(hex === '0' ? '' : hex, 'hex');
  // Left-pad to the length we expect. int -> bytes loses leading zero bytes, and
  // a short buffer would fail the multicodec check for the wrong reason.
  if (expectedLen && buf.length < expectedLen) {
    buf = Buffer.concat([Buffer.alloc(expectedLen - buf.length), buf]);
  }
  return buf;
}

/** A fresh Ed25519 keypair as a 32-byte seed, hex. */
export function generateSeed() {
  const { privateKey } = generateKeyPairSync('ed25519');
  // The seed is the last 32 bytes of the PKCS#8 DER for an Ed25519 key.
  return privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(-32).toString('hex');
}

/** The raw 32-byte public key for a private or public KeyObject. */
export function publicKeyBytes(key) {
  const pub = key.type === 'private' ? createPublicKey(key) : key;
  // An Ed25519 SPKI is a fixed 12-byte header followed by the raw key.
  return pub.export({ type: 'spki', format: 'der' }).subarray(-32);
}

/** did:key:z6Mk… for a Node Ed25519 private key object. */
export function didOf(privateKey) {
  const mb = 'z' + base58encode(Buffer.concat([MULTICODEC_ED25519, publicKeyBytes(privateKey)]));
  if (mb.length !== MULTIBASE_LEN) throw new Error(`internal: multibase 길이 ${mb.length}`);
  return 'did:key:' + mb;
}

/**
 * The Ed25519 public key inside a did:key, as a Node KeyObject ready to verify.
 * Mirrors the server's didkey.py: same length check, same multicodec check,
 * same refusal of everything that is not ed25519-pub.
 */
export function publicKeyFromDid(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error(`bad did:key: did:key:z6Mk… 형식이 아닙니다 (${did})`);
  }
  const mb = did.slice('did:key:'.length);
  if (mb.length !== MULTIBASE_LEN) {
    throw new Error(`bad did:key: multibase ${MULTIBASE_LEN}자를 기대했는데 ${mb.length}자입니다`);
  }
  const decoded = base58decode(mb.slice(1), 34);
  if (decoded.length !== 34 || !decoded.subarray(0, 2).equals(MULTICODEC_ED25519)) {
    throw new Error('bad did:key: ed25519-pub (z6Mk…) 키만 허용됩니다');
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, decoded.subarray(2)]),
    format: 'der',
    type: 'spki',
  });
}

/** True if `did` parses as an Ed25519 did:key. Never throws. */
export function isDid(did) {
  try {
    publicKeyFromDid(did);
    return true;
  } catch {
    return false;
  }
}

/**
 * The identity fingerprint: first 16 lowercase hex of SHA-256 of the did:key
 * STRING. Hashing the key bytes instead would make the path unreachable from a
 * DID printed in a message, which is the only form a reader ever has.
 */
export function fingerprint(did) {
  publicKeyFromDid(did); // refuse to name a path for something that is not a key we accept
  return createHash('sha256').update(did, 'utf8').digest('hex').slice(0, 16);
}

/** Where a DID's identity note lives: /kv/did-<first 2>/<remaining 14>. */
export function notePath(did) {
  const fp = fingerprint(did);
  return { ns: `did-${fp.slice(0, 2)}`, key: fp.slice(2), path: `/kv/did-${fp.slice(0, 2)}/${fp.slice(2)}` };
}

/** The pre-shard path older notes used. Readers fall back to it. */
export function legacyNotePath(did) {
  const fp = fingerprint(did);
  return { ns: 'did', key: fp, path: `/kv/did/${fp}` };
}
