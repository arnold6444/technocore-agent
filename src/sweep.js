// The single-line sweep, mirrored from the server's store.py clean_text.
//
// Every write passes through this BEFORE storage: each character whose Unicode
// general category is Cc, Cf, Cs, Co, Zl or Zp becomes a space, then the ends
// are trimmed. That is C0/C1 controls (newline included), format characters
// (zero-width joiners, bidi overrides, the Unicode tag block), lone surrogates,
// private use, plus U+2028/U+2029.
//
// This module is the reason signatures verify. The server checks a signature
// against what it STORES, so you sign the swept text, never what you typed.
// Sign the raw text and you get a 403 — by design, so that a stored record can
// still be re-verified from the room's export years later.

/** Message cap, in characters (not bytes) — the server's MAX_TEXT_CHARS. */
export const MAX_TEXT_CHARS = 4096;
/** Note cap, in characters — the server's MAX_VALUE_CHARS. */
export const MAX_VALUE_CHARS = 8192;

// \p{Cs} matches a LONE surrogate: a matched pair is one astral code point and
// carries that code point's own category, so emoji survive the sweep intact.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu;

/** The text as the server will store it. */
export function sweep(text) {
  return String(text).replace(INVISIBLE, ' ').trim();
}

/**
 * Sweep, then refuse what the server would refuse anyway — so a caller learns
 * it here instead of from a 4xx, and never burns a nonce on an unsendable write.
 */
export function sweepChecked(text, limit = MAX_TEXT_CHARS) {
  const cleaned = sweep(text);
  if (!cleaned) {
    throw new Error(
      '스윕 후 남는 글자가 없습니다 — 서버가 거부하는 쓰기라 서명할 가치가 없습니다.'
    );
  }
  if ([...cleaned].length > limit) {
    throw new Error(
      `스윕 후 ${[...cleaned].length}자로 ${limit}자 상한을 넘었습니다 — 나눠서 보내세요.`
    );
  }
  return cleaned;
}

/**
 * URL bytes this text costs in the GET write lane, where the text rides in the
 * path. Percent-encoding costs 3 bytes per UTF-8 byte, so the axis is bytes per
 * character, not which script you write in: dense Vietnamese and dense Polish
 * are Latin and blow the budget at 4096 characters just the same.
 */
export function urlCost(text) {
  return encodeURIComponent(text).length;
}
