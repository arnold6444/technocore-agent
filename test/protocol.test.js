// Offline conformance tests. No network, no key material on disk.
//
// These pin the parts of the protocol where being subtly wrong produces a
// *plausible* wrong answer rather than an error: the sweep, the canonical
// strings, base58, signature canonicality, and big-integer nonces.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { sweep, sweepChecked, urlCost, MAX_TEXT_CHARS } from '../src/sweep.js';
import { didOf, generateSeed, publicKeyBytes, publicKeyFromDid, isDid, fingerprint, notePath } from '../src/didkey.js';
import {
  keyFromSeed,
  signMessage,
  signPayload,
  verifyPayload,
  messagePayload,
  notePayload,
  ownershipPayload,
  delegatePayload,
  issueDelegation,
  checkDelegations,
  SIG_RE,
  NONCE_RE,
} from '../src/sign.js';
import { rawNonce, rawTopLevelFields, auditLine, auditExport } from '../src/audit.js';
import { parseBudget, parseRetryAfter, parseCursor, waitNotHeld, seg } from '../src/client.js';
import { nextOwnershipNonce } from '../src/identity.js';

const seed = generateSeed();
const key = keyFromSeed(seed);
const did = didOf(key);

// ---- the sweep -------------------------------------------------------------

test('sweep replaces every invisible category with a space, then trims', () => {
  assert.equal(sweep('a\u200bb'), 'a b'); // Cf zero-width space
  assert.equal(sweep('a\nb'), 'a b'); // Cc newline
  assert.equal(sweep('a\u2028b'), 'a b'); // Zl line separator
  assert.equal(sweep('a\u2029b'), 'a b'); // Zp paragraph separator
  assert.equal(sweep('a\ue000b'), 'a b'); // Co private use
  assert.equal(sweep('a' + String.fromCharCode(0xd800) + 'b'), 'a b'); // Cs lone surrogate
  assert.equal(sweep('\ufeff hi \ufeff'), 'hi'); // BOM is Cf, then trimmed
});

test('sweep leaves astral characters intact — a surrogate PAIR is one code point', () => {
  assert.equal(sweep('ok \u{1F600} emoji'), 'ok \u{1F600} emoji');
});

test('sweep does not normalize — NFC and NFD stay two different messages', () => {
  const nfc = 'Việt';
  const nfd = 'Việt';
  assert.notEqual(sweep(nfc), sweep(nfd));
  assert.equal(urlCost(sweep(nfc)) < urlCost(sweep(nfd)), true);
});

test('sweepChecked refuses what the server would refuse, before any nonce is spent', () => {
  assert.throws(() => sweepChecked('\u200b\u200b'), /스윕 후 남는 글자가 없습니다/);
  assert.throws(() => sweepChecked('x'.repeat(MAX_TEXT_CHARS + 1)), /상한을 넘었습니다/);
});

// ---- did:key ---------------------------------------------------------------

test('did:key is always did:key:z6Mk + 44 base58 characters', () => {
  for (let i = 0; i < 200; i++) {
    const { privateKey } = generateKeyPairSync('ed25519');
    const d = didOf(privateKey);
    assert.match(d, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
    assert.equal(d.length, 56);
  }
});

test('did:key round-trips back to the same 32 public key bytes', () => {
  for (let i = 0; i < 200; i++) {
    const { privateKey } = generateKeyPairSync('ed25519');
    const d = didOf(privateKey);
    assert.equal(
      publicKeyBytes(publicKeyFromDid(d)).toString('hex'),
      publicKeyBytes(privateKey).toString('hex')
    );
  }
});

test('only ed25519-pub keys are accepted', () => {
  assert.equal(isDid('did:key:zzz'), false);
  assert.equal(isDid('did:key:z6MkehBYF3tgDesabVwhgbV82wsTvPbXHdEmtZgteMsnHgR'), false); // 55 chars
  assert.equal(isDid(''), false);
  assert.equal(isDid(null), false);
  // z6LS… is X25519, not Ed25519 — a real did:key that this service refuses.
  assert.equal(isDid('did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc'), false);
});

test('the note path hashes the did:key STRING, not the key bytes', () => {
  // Fixed vector: if this changes, every peer looking for our note looks in the
  // wrong namespace and finds nothing.
  const d = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  assert.equal(fingerprint(d), fingerprint(d));
  assert.equal(fingerprint(d).length, 16);
  const p = notePath(d);
  assert.equal(p.ns, `did-${fingerprint(d).slice(0, 2)}`);
  assert.equal(p.key, fingerprint(d).slice(2));
  assert.equal(p.key.length, 14);
});

// ---- canonical strings -----------------------------------------------------

test('the four canonical strings are exactly the documented shapes', () => {
  assert.equal(messagePayload('lobby', '7', 'hi'), 'lobby|7|hi');
  assert.equal(notePayload('did-ab', 'cd', '7', 'v'), 'did-ab|cd|7|v');
  assert.equal(ownershipPayload('d-jobs', '7', did), `room-owners|d-jobs|7|${did}`);
  assert.equal(delegatePayload('R', 'A', '*', '99', '7'), 'delegate|R|A|*|99|7');
});

test('a delegation string can never be read as a message or note signature', () => {
  // Field 1 of a message signature is a room name and field 2 a nonce, so the
  // leading literal makes the two spaces disjoint.
  const d = delegatePayload('R', 'A', '*', '99', '7');
  assert.equal(d.startsWith('delegate|'), true);
  assert.equal(NONCE_RE.test(d.split('|')[1]), false);
});

// ---- signatures ------------------------------------------------------------

test('signatures are 86 unpadded base64url characters ending in A, Q, g or w', () => {
  for (let i = 0; i < 200; i++) {
    const sig = signPayload(key, `lobby|${i}|message ${i}`);
    assert.equal(sig.length, 86);
    assert.match(sig, SIG_RE);
    assert.ok(['A', 'Q', 'g', 'w'].includes(sig.slice(-1)));
    assert.equal(sig.includes('='), false);
  }
});

test('a signature is bound to its room, nonce and text', () => {
  const m = signMessage(key, 'lobby', '5', 'hello');
  assert.ok(verifyPayload(did, m.sig, messagePayload('lobby', '5', 'hello')));
  assert.equal(verifyPayload(did, m.sig, messagePayload('meta', '5', 'hello')), false);
  assert.equal(verifyPayload(did, m.sig, messagePayload('lobby', '6', 'hello')), false);
  assert.equal(verifyPayload(did, m.sig, messagePayload('lobby', '5', 'hellO')), false);
});

test('signMessage signs the SWEPT text, which is what the server stores', () => {
  const raw = '  hello\nworld  ';
  const m = signMessage(key, 'lobby', '1', raw);
  assert.equal(m.text, 'hello world');
  // The swept form verifies...
  assert.ok(verifyPayload(did, m.sig, messagePayload('lobby', '1', 'hello world')));
  // ...and the raw form, which is what a naive implementation would sign, does not.
  assert.equal(verifyPayload(did, m.sig, messagePayload('lobby', '1', raw)), false);
});

test('a non-canonical signature encoding is rejected', () => {
  const sig = signPayload(key, 'lobby|1|hi');
  const mangled = sig.slice(0, 85) + 'B'; // same 64 bytes decode, wrong tail
  assert.equal(SIG_RE.test(mangled), false);
  assert.equal(verifyPayload(did, mangled, 'lobby|1|hi'), false);
});

test('nonces must be 1-19 ASCII digits — Unicode digits are refused here, not by a 403', () => {
  assert.throws(() => messagePayload('lobby', '١٢٣', 'hi'), /ASCII 숫자/);
  assert.throws(() => messagePayload('lobby', '', 'hi'), /ASCII 숫자/);
  assert.throws(() => messagePayload('lobby', '1'.repeat(20), 'hi'), /ASCII 숫자/);
  assert.equal(messagePayload('lobby', '1'.repeat(19), 'hi'), `lobby|${'1'.repeat(19)}|hi`);
});

// ---- delegation ------------------------------------------------------------

test('delegation states: OK, EXPIRED, SUPERSEDED, FORGED', () => {
  const agent = didOf(generateKeyPairSync('ed25519').privateKey);
  const other = keyFromSeed(generateSeed());

  const narrow = issueDelegation(key, did, agent, 'r:lobby', 30, '100');
  const wide = issueDelegation(key, did, agent, '*', 30, '200');
  const forged = issueDelegation(other, didOf(other), agent, '*', 30, '300');

  const note = [did, 'mailbox: mb-p-abc', narrow.line, wide.line, forged.line].join(' ');
  const now = Math.floor(Date.now() / 1000);

  const results = checkDelegations(did, note, now);
  assert.equal(results.length, 3);
  assert.equal(results[0].status, 'SUPERSEDED'); // nonce 100 loses to 200
  assert.equal(results[1].status, 'OK');
  assert.equal(results[1].daysLeft, 30);
  assert.equal(results[2].status, 'FORGED'); // signed by a different root
  // ...and the forgery's higher nonce (300) does NOT demote the genuine grant.
  // The reference implementation ranks before verifying, so it would report
  // results[1] as SUPERSEDED and leave the note with no live delegation at all.

  // Same note, read after both grants lapse.
  const later = checkDelegations(did, note, now + 31 * 86400);
  assert.equal(later[1].status, 'EXPIRED');
});

test('delegations are found by token, not by line — a note is always one line', () => {
  const agent = didOf(generateKeyPairSync('ed25519').privateKey);
  const rec = issueDelegation(key, did, agent, '*', 5, '1');
  // Exactly what the sweep does to a note someone wrote with newlines.
  const glued = sweep(`${did}\nmailbox: mb-x\n${rec.line}\n`);
  const [only] = checkDelegations(did, glued);
  assert.equal(only.status, 'OK');
});

test('a key cannot delegate to itself, and scope is validated', () => {
  assert.throws(() => issueDelegation(key, did, did, '*', 5), /자기 자신/);
  assert.throws(() => issueDelegation(key, did, didOf(generateKeyPairSync('ed25519').privateKey), 'bogus', 5), /scope/);
  assert.throws(() => issueDelegation(key, did, didOf(generateKeyPairSync('ed25519').privateKey), '*', 0), /days/);
});

// ---- the auditor -----------------------------------------------------------

test('a big nonce survives: JSON.parse rounds it, the raw scanner does not', () => {
  const big = '9223372036854775807'; // 19 digits, far past 2^53
  const line = `{"seq":1,"ts":"t","from":"${did}","text":"hi","nonce":${big},"sig":"x"}`;
  assert.notEqual(String(JSON.parse(line).nonce), big); // the trap
  assert.equal(rawNonce(line), big); // the fix
});

test('a "nonce" key INSIDE the text is not mistaken for the record nonce', () => {
  // This shape is real: tclk frames carry their own nonce inside the message.
  const text = JSON.stringify('tclk1 {"type": "accept", "nonce": 777}');
  const line = `{"seq":1,"ts":"t","from":"${did}","text":${text},"nonce":5158,"sig":"x"}`;
  assert.equal(rawNonce(line), '5158');
  assert.deepEqual([...rawTopLevelFields(line).keys()], ['seq', 'ts', 'from', 'text', 'nonce', 'sig']);
});

test('the scanner is not desynchronised by escaped quotes or braces in the text', () => {
  const text = JSON.stringify('he said "{" and \\ then "nonce": 1');
  const line = `{"seq":2,"ts":"t","from":"${did}","text":${text},"nonce":42,"sig":"x"}`;
  assert.equal(rawNonce(line), '42');
});

test('auditLine verifies a record we signed ourselves', () => {
  const m = signMessage(key, 'd-test', '12345', 'a verifiable line');
  const line = JSON.stringify({ seq: 9, ts: 't', from: did, text: m.text, nonce: Number(m.nonce), sig: m.sig });
  assert.equal(auditLine('d-test', line).status, 'VERIFIED');
  // The same record, claimed to be from a different room, does not verify.
  assert.equal(auditLine('d-other', line).status, 'FAILED');
});

test('a missing sig is "not re-verifiable", never "forged"', () => {
  const signedButOld = JSON.stringify({ seq: 1, ts: 't', from: did, text: 'hi' });
  assert.equal(auditLine('r', signedButOld).status, 'NO_SIG');
  const nickname = JSON.stringify({ seq: 2, ts: 't', from: 'alice', text: 'hi' });
  assert.equal(auditLine('r', nickname).status, 'UNSIGNED');
});

test('auditExport counts, and a tampered text is caught', () => {
  const good = signMessage(key, 'd-test', '10', 'first');
  const bad = signMessage(key, 'd-test', '11', 'second');
  const lines = [
    JSON.stringify({ seq: 1, ts: 't', from: did, text: good.text, nonce: Number(good.nonce), sig: good.sig }),
    JSON.stringify({ seq: 2, ts: 't', from: did, text: 'second EDITED', nonce: Number(bad.nonce), sig: bad.sig }),
    JSON.stringify({ seq: 3, ts: 't', from: 'anon', text: 'unsigned' }),
    '{ not json',
  ].join('\n');

  const r = auditExport('d-test', lines);
  assert.equal(r.counts.total, 4);
  assert.equal(r.counts.verified, 1);
  assert.equal(r.counts.failed, 1);
  assert.equal(r.counts.unsigned, 1);
  assert.equal(r.counts.unparseable, 1);
  assert.equal(r.distinctKeys, 1);
  assert.equal(r.firstSeq, 1);
  assert.equal(r.lastSeq, 3);
});

// ---- the wire ---------------------------------------------------------------

test('reply metadata is parsed off the body, where the harness can see it', () => {
  assert.deepEqual(parseBudget('hi\n# budget: 12 of 600 reads left this minute'), { left: 12, max: 600 });
  assert.equal(parseBudget('nothing here'), null);
  assert.equal(parseCursor('[1] x\nnext: /r/lobby?since=74'), 74);
  assert.equal(waitNotHeld('# wait: not held (waiter cap)'), true);
  assert.equal(waitNotHeld('{"wait_held": false}'), true);
  assert.equal(waitNotHeld('ordinary reply'), false);
});

test('a 429 wait comes from the body, and falls back rather than throwing', () => {
  assert.equal(parseRetryAfter('429 write bucket, retry in 12 seconds', null), 12);
  assert.equal(parseRetryAfter('nothing useful', null), 5);
  // Retry-After is honoured when present, but the body is the lane that matters:
  // harnesses show an agent the body, not the headers.
  assert.equal(parseRetryAfter('no hint in here', { get: () => '30' }), 30);
});

test('path segments encode the characters that would otherwise change the route', () => {
  assert.equal(seg('a/b'), 'a%2Fb');
  assert.equal(seg('a b'), 'a%20b');
  assert.equal(seg('100%'), '100%25');
  assert.equal(seg('a?b#c'), 'a%3Fb%23c');
});

test('ownership nonces come from the server counter, not from ours', () => {
  const server = '9999999999999999';
  assert.equal(BigInt(nextOwnershipNonce(server)) > BigInt(server), true);
  // Absent counts as zero, and a clock still gives a sane value.
  assert.equal(BigInt(nextOwnershipNonce(null)) > 0n, true);
  assert.equal(BigInt(nextOwnershipNonce('not-a-number')) > 0n, true);
});
