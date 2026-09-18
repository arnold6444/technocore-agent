// The canonical strings, and the signatures over them.
//
// The whole of the signed lane is this: the server verifies a signature over
// exactly what it stores, and these four builders are that "exactly".
//
//   message:   <room>|<nonce>|<swept text>
//   note:      <ns>|<key>|<nonce>|<swept value>
//   ownership: room-owners|d-<room>|<nonce>|<the same did:key>   (a note, above,
//              named here because getting its field order wrong loses a room)
//   delegate:  delegate|<root-did>|<agent-did>|<scope>|<expires>|<nonce>
//
// Note the leading literal on a delegation. Field 1 of a message signature is a
// room name and field 2 a nonce, so a 'delegate|...' string reads as neither of
// the others, and a signature over one is never a valid signature over another.

import { createPrivateKey, sign as edSign, verify as edVerify } from 'node:crypto';
import { publicKeyFromDid } from './didkey.js';
import { sweepChecked, MAX_TEXT_CHARS, MAX_VALUE_CHARS } from './sweep.js';

/** PKCS#8 DER header for an Ed25519 private key; the 32-byte seed follows it. */
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/**
 * 1-19 ASCII digits, exactly the server's NONCE_RE.
 *
 * Deliberately not a `isDigit`-style check: JavaScript and Python both have
 * digit tests that accept non-ASCII Unicode digits, which this regex and the
 * server's both refuse. Signing one and being told it was good, then getting a
 * 403, is an expensive way to find that out.
 */
export const NONCE_RE = /^[0-9]{1,19}$/;

/**
 * 86 unpadded base64url characters, and canonical.
 *
 * 64 bytes leave the last character's low four bits zero, so it is always one
 * of A, Q, g, w. Sixteen strings decode to the same 64 bytes and only the one
 * the encoder produces is accepted — never hand-edit a signature's tail.
 */
export const SIG_RE = /^[A-Za-z0-9_-]{85}[AQgw]$/;

/** A delegation scope: everything, one room, or one note namespace. */
export const SCOPE_RE = /^(\*|r:[a-z0-9][a-z0-9_-]{0,47}|kv:[a-z0-9][a-z0-9_-]{0,47})$/;

const DELEGATE_TOKEN = 'delegate:';
const DELEGATE_FIELDS = 5; // agent, scope, expires, nonce, sig

/** A Node Ed25519 private key from a 32-byte hex seed. */
export function keyFromSeed(seedHex) {
  if (!/^[0-9a-fA-F]{64}$/.test(String(seedHex).trim())) {
    throw new Error('시드는 64자리 16진수여야 합니다.');
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(String(seedHex).trim(), 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
}

function assertNonce(nonce) {
  const n = String(nonce);
  if (!NONCE_RE.test(n)) {
    throw new Error(`nonce는 ASCII 숫자 1~19자리여야 합니다 (받은 값: ${n})`);
  }
  return n;
}

// ---- canonical strings -----------------------------------------------------

/** `<room>|<nonce>|<text>` - text ALREADY swept. */
export function messagePayload(room, nonce, sweptText) {
  return `${room}|${assertNonce(nonce)}|${sweptText}`;
}

/** `<ns>|<key>|<nonce>|<value>` - value ALREADY swept. */
export function notePayload(ns, key, nonce, sweptValue) {
  return `${ns}|${key}|${assertNonce(nonce)}|${sweptValue}`;
}

/**
 * `room-owners|d-<room>|<nonce>|<did>` - the claim, which must be signed by the
 * same key it stores. Parsing a key is not proof that the caller holds it.
 */
export function ownershipPayload(room, nonce, did) {
  return notePayload('room-owners', room, nonce, did);
}

/** `room-allow|d-<room>|<nonce>|<space-separated dids>` - owner's key only. */
export function allowPayload(room, nonce, value) {
  return notePayload('room-allow', room, nonce, value);
}

/** `delegate|<root>|<agent>|<scope>|<expires>|<nonce>` - never seen by the server. */
export function delegatePayload(root, agent, scope, expires, nonce) {
  return `delegate|${root}|${agent}|${scope}|${expires}|${assertNonce(nonce)}`;
}

// ---- signing ---------------------------------------------------------------

/** 86 unpadded base64url characters, the encoding the server's SIG_RE expects. */
export function signPayload(privateKey, payload) {
  const sig = edSign(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64url');
  // Belt and braces: re-encoding the raw 64 bytes is canonical by construction,
  // but the server rejects a non-canonical signature with no useful message.
  if (!SIG_RE.test(sig)) throw new Error(`internal: 비정규 서명이 생성됨 (${sig})`);
  return sig;
}

/** Verify a base64url signature over `payload` against a did:key. Never throws. */
export function verifyPayload(did, sig, payload) {
  try {
    if (!SIG_RE.test(sig)) return false;
    return edVerify(
      null,
      Buffer.from(payload, 'utf8'),
      publicKeyFromDid(did),
      Buffer.from(sig, 'base64url')
    );
  } catch {
    return false;
  }
}

/** Sweep, sign, and hand back everything a signed say needs. */
export function signMessage(privateKey, room, nonce, rawText) {
  const text = sweepChecked(rawText, MAX_TEXT_CHARS);
  return {
    text,
    nonce: assertNonce(nonce),
    sig: signPayload(privateKey, messagePayload(room, nonce, text)),
  };
}

/** Sweep, sign, and hand back everything a signed note write needs. */
export function signNote(privateKey, ns, key, nonce, rawValue) {
  const value = sweepChecked(rawValue, MAX_VALUE_CHARS);
  return {
    value,
    nonce: assertNonce(nonce),
    sig: signPayload(privateKey, notePayload(ns, key, nonce, value)),
  };
}

// ---- delegation ------------------------------------------------------------

/**
 * Every delegation record in a note, found by TOKEN rather than by line.
 *
 * A note is always one line - the sweep turns every newline into a space - so
 * records are separated by whitespace and nothing else. Scanning for the token
 * reads `mailbox: mb-x delegate: <did> ...` correctly, and the read lane's
 * banner and budget footer carry no such token so they fall out for free.
 */
export function parseDelegations(noteBody) {
  const fields = String(noteBody).split(/\s+/).filter(Boolean);
  const out = [];
  for (let i = 0; i < fields.length; i++) {
    if (fields[i] !== DELEGATE_TOKEN) continue;
    const record = fields.slice(i + 1, i + 1 + DELEGATE_FIELDS);
    if (record.length === DELEGATE_FIELDS) {
      const [agent, scope, expires, nonce, sig] = record;
      out.push({ agent, scope, expires, nonce, sig });
    }
  }
  return out;
}

/**
 * Audit a note's delegations against a root DID. Needs no key and no network,
 * which is the property that matters: a delegation is checkable by anyone from
 * the note text alone.
 *
 * Highest nonce wins per agent. That is not tidiness - the note is
 * world-writable, so anyone can re-add a SUPERSEDED record that really was
 * signed by the root and has not expired, and it verifies. If every valid
 * record counted, narrowing a grant from `*` to `r:lobby` could be undone by
 * putting the old one back.
 *
 * DELIBERATE DEVIATION from the reference scripts/sign.py: supersession is
 * ranked over the records that VERIFY against this root, not over every record
 * in the note. The reference ranks first and verifies second, so a stranger who
 * writes `delegate: <your agent> * 9999999999 <huge nonce> <junk sig>` into your
 * world-writable note makes every genuine grant report as SUPERSEDED — a denial
 * of service on the audit, from an unsigned string anyone can write. Ranking
 * among verified records closes that and keeps the property the rule exists for:
 * a real earlier grant still cannot undo a real later one, because both verify.
 * Expired-but-verified records stay in the ranking, so a lapsed re-issue fails
 * closed rather than resurrecting the grant it replaced.
 */
export function checkDelegations(rootDid, noteBody, now = Math.floor(Date.now() / 1000)) {
  const records = parseDelegations(noteBody);

  const verified = records.map((r) =>
    verifyPayload(rootDid, r.sig, delegatePayload(rootDid, r.agent, r.scope, r.expires, r.nonce))
  );

  const best = new Map();
  records.forEach((r, i) => {
    if (!verified[i]) return;
    const rank = NONCE_RE.test(r.nonce) ? BigInt(r.nonce) : -1n;
    const held = best.get(r.agent);
    if (!held || rank >= held.rank) best.set(r.agent, { rank, index: i });
  });
  const current = new Set([...best.values()].map((v) => v.index));

  return records.map((r, i) => {
    if (!verified[i]) {
      // Not "invalid": forged, or for somebody else. A record that fails here
      // was signed by a key that is not this root, which in a note anyone can
      // write to is the ordinary case and not an error.
      return { ...r, status: 'FORGED' };
    }
    if (!NONCE_RE.test(r.expires) || Number(r.expires) <= now) {
      return { ...r, status: 'EXPIRED' };
    }
    // Checked after the signature and the expiry, so a superseded record is
    // only ever reported as superseded when it was otherwise a live grant.
    if (!current.has(i)) return { ...r, status: 'SUPERSEDED' };
    // Rounded up: a 30-day grant is "30d left" a second later, where flooring
    // would report 29 and make every fresh delegation look already shortened.
    return { ...r, status: 'OK', daysLeft: Math.ceil((Number(r.expires) - now) / 86400) };
  });
}

/**
 * One `delegate: ...` line to append to the root's own DID note.
 *
 * Expiry is the ONLY revocation this format has - a reader holding a cached
 * copy of the note cannot see a record you deleted - so issue for days, not
 * years, and re-issue.
 */
export function issueDelegation(privateKey, rootDid, agentDid, scope, days, nonce) {
  if (!SCOPE_RE.test(scope)) {
    throw new Error(`scope는 '*', 'r:<room>', 'kv:<ns>' 중 하나여야 합니다 (받은 값: ${scope})`);
  }
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    throw new Error(`days는 1~3650 사이의 정수여야 합니다 (받은 값: ${days})`);
  }
  if (rootDid === agentDid) {
    throw new Error('키는 자기 자신에게 위임할 수 없습니다 — 이미 스스로를 위해 행동합니다.');
  }
  publicKeyFromDid(agentDid); // refuse to delegate to something that is not a key
  const n = assertNonce(nonce ?? Date.now());
  const expires = String(Math.floor(Date.now() / 1000) + days * 86400);
  const sig = signPayload(privateKey, delegatePayload(rootDid, agentDid, scope, expires, n));
  return {
    line: `${DELEGATE_TOKEN} ${agentDid} ${scope} ${expires} ${n} ${sig}`,
    expires,
    nonce: n,
    sig,
  };
}
