/**
 * DELIBERATELY BROKEN MODE — never used by the honest extension path.
 *
 * Implements Boneh-Shoup v0.6 §23.7, equation 23.23. A receiver deviates in
 * the first 128 rows and relies on known plaintext from a later protocol step
 * to recover one bit of the sender's r per row. This module is imported only
 * by the learner-controlled broken-mode handler.
 */
import type { BaseOTSetup } from './base';
import {
  hashRow,
  type MaskedMessages,
  type MessagePairs,
  type ReceiverMessageState,
  type RunOptions,
  type SenderOutputState,
} from './iknp';
import { rowAt } from './transpose';

export interface RecoveredSecret {
  bits: Uint8Array;
  bytes: Uint8Array;
}

export interface CorruptAttackResult {
  recovered: RecoveredSecret;
  recoveredExactly: boolean;
  chosenCorrectCount: number;
  bothMessagesRecoveredCount: number;
}

export interface CorruptRunOptions extends RunOptions {
  onProbe?: (bits: Uint8Array, completed: number) => void;
}

function equalPrefix(a: Uint8Array, b: Uint8Array, length: number): boolean {
  let diff = 0;
  for (let i = 0; i < length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && equalPrefix(a, b, a.length);
}

function xorMessage(
  ciphertext: Uint8Array,
  mask: Uint8Array,
  index: number,
  messageBytes: number,
): Uint8Array {
  const out = new Uint8Array(messageBytes);
  for (let b = 0; b < messageBytes; b += 1) {
    out[b] = ciphertext[index * messageBytes + b] ^ mask[b];
  }
  return out;
}

export function makeCorruptReceiverState(
  honest: ReceiverMessageState,
): ReceiverMessageState {
  if (honest.count < 128 || honest.rowBytes !== 16) {
    throw new RangeError('equation 23.23 needs at least 128 transfers and 128-bit rows');
  }
  const choices = honest.choices.slice();
  const pRows = honest.pRows.slice();
  for (let j = 0; j < 128; j += 1) {
    choices[j] = 1;
    const u = rowAt(honest.uRows, j);
    const v = rowAt(honest.vRows, j);
    const p = pRows.subarray(j * 16, (j + 1) * 16);
    for (let b = 0; b < 16; b += 1) p[b] = u[b] ^ v[b];
    // p*_j = v_j xor u_j xor (C[1] xor e_j), and C[1] = 0^128.
    p[j >>> 3] ^= 1 << (7 - (j & 7));
  }
  return { ...honest, choices, pRows };
}

export async function recoverR(
  receiver: ReceiverMessageState,
  ciphertexts: MaskedMessages,
  knownMessages: MessagePairs,
  options: CorruptRunOptions = {},
): Promise<RecoveredSecret> {
  const recovered = new Uint8Array(128);
  const bytes = new Uint8Array(16);
  for (let j = 0; j < 128; j += 1) {
    const knownMask = new Uint8Array(knownMessages.messageBytes);
    for (let b = 0; b < knownMessages.messageBytes; b += 1) {
      knownMask[b] =
        ciphertexts.one[j * knownMessages.messageBytes + b] ^
        knownMessages.one[j * knownMessages.messageBytes + b];
    }
    const u = rowAt(receiver.uRows, j);
    const uXorEj = u.slice();
    uXorEj[j >>> 3] ^= 1 << (7 - (j & 7));
    const zeroCandidate = hashRow(j + 1, 1, u);
    const oneCandidate = hashRow(j + 1, 1, uXorEj);
    const matchedZero = equalPrefix(knownMask, zeroCandidate, knownMessages.messageBytes);
    const matchedOne = equalPrefix(knownMask, oneCandidate, knownMessages.messageBytes);
    if (matchedZero === matchedOne) {
      throw new Error(`probe ${j + 1} did not identify exactly one sender bit`);
    }
    recovered[j] = matchedOne ? 1 : 0;
    if (recovered[j] === 1) bytes[j >>> 3] |= 1 << (7 - (j & 7));
    options.onProbe?.(recovered.slice(), j + 1);
    options.onProgress?.({ phase: 'recover sender r', completed: j + 1, total: 128 });
    if (options.signal?.aborted) throw new DOMException('OT extension cancelled', 'AbortError');
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return { bits: recovered, bytes };
}

export async function decryptBoth(
  receiver: ReceiverMessageState,
  recovered: RecoveredSecret,
  ciphertexts: MaskedMessages,
  messages: MessagePairs,
  options: RunOptions = {},
): Promise<number> {
  let both = 0;
  for (let start = 128; start < receiver.count; start += 4096) {
    if (options.signal?.aborted) throw new DOMException('OT extension cancelled', 'AbortError');
    const end = Math.min(receiver.count, start + 4096);
    for (let i = start; i < end; i += 1) {
      const u = rowAt(receiver.uRows, i);
      const q = u.slice();
      if (receiver.choices[i] === 2) {
        for (let b = 0; b < 16; b += 1) q[b] ^= recovered.bytes[b];
      }
      const qXorR = q.slice();
      for (let b = 0; b < 16; b += 1) qXorR[b] ^= recovered.bytes[b];
      const one = xorMessage(ciphertexts.one, hashRow(i + 1, 1, q), i, messages.messageBytes);
      const two = xorMessage(ciphertexts.two, hashRow(i + 1, 2, qXorR), i, messages.messageBytes);
      const expectedOne = messages.one.subarray(
        i * messages.messageBytes,
        (i + 1) * messages.messageBytes,
      );
      const expectedTwo = messages.two.subarray(
        i * messages.messageBytes,
        (i + 1) * messages.messageBytes,
      );
      if (equalBytes(one, expectedOne) && equalBytes(two, expectedTwo)) both += 1;
    }
    options.onProgress?.({ phase: 'open both messages', completed: end, total: receiver.count });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return both;
}

export async function assessCorruptAttack(
  setup: BaseOTSetup,
  receiver: ReceiverMessageState,
  sender: SenderOutputState,
  ciphertexts: MaskedMessages,
  messages: MessagePairs,
  options: CorruptRunOptions = {},
): Promise<CorruptAttackResult> {
  const recovered = await recoverR(receiver, ciphertexts, messages, options);
  const recoveredExactly = equalBytes(recovered.bits, setup.senderChoiceBits);
  let knownPlaintextCorrect = 0;
  for (let j = 0; j < 128; j += 1) {
    const knownMask = sender.y1.subarray(j * 32, (j + 1) * 32);
    const opened = xorMessage(ciphertexts.one, knownMask, j, messages.messageBytes);
    const expected = messages.one.subarray(
      j * messages.messageBytes,
      (j + 1) * messages.messageBytes,
    );
    if (equalBytes(opened, expected)) knownPlaintextCorrect += 1;
  }
  const bothMessagesRecoveredCount = await decryptBoth(
    receiver,
    recovered,
    ciphertexts,
    messages,
    options,
  );
  return {
    recovered,
    recoveredExactly,
    chosenCorrectCount: knownPlaintextCorrect + bothMessagesRecoveredCount,
    bothMessagesRecoveredCount,
  };
}
