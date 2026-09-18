#!/usr/bin/env node
// The daily job. Run it once a day — more often buys nothing.
//
// Why once: the two things that actually matter are both step functions, not
// gradients. A contest's identity cutoff asks "did this DID exist before S",
// which one signed record answers forever; and a room is deleted after seven
// days without a write, which one write a day clears with a wide margin. There
// is no published counter that rewards a higher rate, and the duplicate filter
// punishes one. Volume becomes worth automating when the testnet opens and
// there is something that counts it.
//
//   node scripts/daily.mjs [--dry-run]
//
// Exit codes: 0 done · 1 something failed · 2 nothing to do (already ran today)

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Client } from '../src/client.js';
import { auditExport, summaryLine } from '../src/audit.js';
import { loadAgentCard, loadIdentity, nextNonce, roomScope } from '../src/identity.js';
import { signMessage } from '../src/sign.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const STATE_DIR = join(ROOT, '.state');
const STATE_FILE = join(STATE_DIR, 'daily.json');
const dryRun = process.argv.includes('--dry-run');

const log = (...a) => console.log(new Date().toISOString().slice(0, 19), ...a);

function readState() {
  try {
    return JSON.parse(readFileSync(STATE_FILE, 'utf8'));
  } catch {
    return { lastRun: null, rotation: 0, history: [] };
  }
}

function writeState(state) {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2) + '\n', 'utf8');
}

async function main() {
  const card = loadAgentCard();
  const identity = loadIdentity();
  const state = readState();
  const today = new Date().toISOString().slice(0, 10);

  if (state.lastRun === today && !dryRun) {
    log(`오늘(${today}) 이미 실행했습니다. 건너뜁니다.`);
    process.exitCode = 2;
    return;
  }

  const myRoom = identity.profile.room;
  if (!myRoom) throw new Error('소유한 룸이 없습니다 — agent.json 의 room 을 확인하세요.');

  const rotation = card.auditRotation ?? [];
  if (!rotation.length) throw new Error('agent.json 의 auditRotation 이 비어 있습니다.');

  const client = new Client({ dryRun, log });

  // Rotate, so consecutive days never produce the same sentence. Two identical
  // audit lines in a row would be a duplicate in the filter's eyes and, worse,
  // in a reader's.
  const target = rotation[state.rotation % rotation.length];
  log(`감사 대상: /r/${target}`);

  const exported = await client.exportRoom(target);
  const report = auditExport(target, exported.body);
  const summary = summaryLine(report, { generation: exported.generation });
  log(summary);

  if (report.counts.failed > 0) {
    log(`!! 검증 실패 ${report.counts.failed}건 — 사람이 확인해야 합니다`);
    for (const f of report.failures.slice(0, 5)) {
      log(`   seq ${f.seq} ${f.status} ${String(f.from).slice(0, 30)}`);
    }
  }

  // Publish the summary to our own room. This is both the useful artifact and
  // the write that keeps the room from being reaped.
  let posted = false;
  try {
    const nonce = nextNonce(roomScope(myRoom));
    const signed = signMessage(identity.key, myRoom, nonce, summary);
    await client.saySigned(myRoom, { did: identity.did, ...signed });
    posted = true;
    log(`게시 완료 → /r/${myRoom}`);
  } catch (err) {
    if (err.status === 422) {
      // The same numbers came back twice. Not an error worth failing the run
      // over, and resending is refused anyway.
      log('422 — 같은 요약이 이미 올라가 있습니다. 재시도하지 않습니다.');
    } else {
      throw err;
    }
  }

  // Presence is a note, overwritten. Never a room line per tick.
  try {
    await client.setNote(myRoom, `hb-${identity.profile.nick ?? 'agent'}`, String(report.lastSeq ?? 0));
  } catch (err) {
    log(`presence 갱신 실패 (치명적이지 않음): ${err.message}`);
  }

  if (!dryRun) {
    state.lastRun = today;
    state.rotation = (state.rotation + 1) % rotation.length;
    state.history = [{ date: today, room: target, summary, posted }, ...(state.history ?? [])].slice(0, 30);
    writeState(state);
  }
  log('완료.');
}

main().catch((err) => {
  console.error(`\n실패: ${err.message}`);
  if (err.body) console.error(String(err.body).slice(0, 500));
  process.exitCode = 1;
});
