/**
 * Boneh-Shoup §23.7 / IKNP-style OT extension for t=2, ell=2,
 * C=(0^n, 1^n), n=128. The protocol mechanics are hand-written here;
 * only AES-CTR (WebCrypto) and SHA-256 (@noble/hashes) are delegated.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { reserveTransferRange, type BaseOTSetup } from './base';
import { expandColumn } from './prf';
import { rowAt, transposeColumnsChunked } from './transpose';

export const ALLOWED_TRANSFER_COUNTS = [1_000, 10_000, 100_000] as const;
export const ROW_BYTES = 16;
export const MESSAGE_BYTES = 16;
export const WORK_CHUNK = 4096;

export interface ProgressUpdate {
  phase: string;
  completed: number;
  total: number;
}

export interface RunOptions {
  signal?: AbortSignal;
  onProgress?: (update: ProgressUpdate) => void;
}

export interface ReceiverMessageState {
  /** Global one-based PRF/hash index; never restarted under the same base keys. */
  firstIndex: number;
  count: number;
  rowBytes: number;
  choices: Uint8Array;
  uRows: Uint8Array;
  vRows: Uint8Array;
  pRows: Uint8Array;
}

export interface SenderOutputState {
  qRows: Uint8Array;
  y1: Uint8Array;
  y2: Uint8Array;
  hashCalls: number;
}

export interface MessagePairs {
  one: Uint8Array;
  two: Uint8Array;
  messageBytes: number;
}

export interface MaskedMessages {
  one: Uint8Array;
  two: Uint8Array;
  messageBytes: number;
}

export interface VerifyResult {
  count: number;
  correctCount: number;
  wrongMessageRejectedCount: number;
  allCorrect: boolean;
}

function assertAllowedCount(count: number): void {
  if (!(ALLOWED_TRANSFER_COUNTS as readonly number[]).includes(count)) {
    throw new RangeError('N must be one of 1,000, 10,000, or 100,000');
  }
}

function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('OT extension cancelled', 'AbortError');
}

async function yieldChunk(options: RunOptions, phase: string, completed: number, total: number) {
  checkAbort(options.signal);
  options.onProgress?.({ phase, completed, total });
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function writeIndex(out: Uint8Array, index: number): void {
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(0, index, false);
}

/** H_{i,a}(x) = SHA-256(uint32be(i) || uint8(a) || x), with i one-based. */
export function hashRow(index: number, branch: 1 | 2, row: Uint8Array): Uint8Array {
  if (!Number.isInteger(index) || index < 1 || index > 0xffffffff) throw new RangeError('hash index must be uint32 and one-based');
  if (row.length !== ROW_BYTES) throw new RangeError('hash row must be 16 bytes');
  const encoded = new Uint8Array(4 + 1 + ROW_BYTES);
  writeIndex(encoded, index);
  encoded[4] = branch;
  encoded.set(row, 5);
  // noble is synchronous. WebCrypto digest would require one awaited call per
  // hash, while the online phase deliberately performs about 3N hashes.
  return sha256(encoded);
}

export function randomChoices(count: number): Uint8Array {
  assertAllowedCount(count);
  const random = new Uint8Array(count);
  for (let offset = 0; offset < count; offset += 65_536) {
    crypto.getRandomValues(random.subarray(offset, Math.min(count, offset + 65_536)));
  }
  const choices = new Uint8Array(count);
  for (let i = 0; i < count; i += 1) choices[i] = (random[i] & 1) + 1;
  return choices;
}

export function createMessagePairs(count: number, messageBytes = MESSAGE_BYTES): MessagePairs {
  assertAllowedCount(count);
  assertMessageBytes(messageBytes);
  const one = new Uint8Array(count * messageBytes);
  const two = new Uint8Array(count * messageBytes);
  for (let i = 0; i < count; i += 1) {
    for (let b = 0; b < messageBytes; b += 1) {
      one[i * messageBytes + b] = (i * 29 + b * 17 + 0x31) & 0xff;
      two[i * messageBytes + b] = (i * 43 + b * 11 + 0xa7) & 0xff;
    }
  }
  return { one, two, messageBytes };
}

export function receiverPRow(
  u: Uint8Array,
  v: Uint8Array,
  choice: 1 | 2,
): Uint8Array {
  if (u.length !== v.length) throw new RangeError('u and v rows must have equal length');
  const p = new Uint8Array(u.length);
  for (let b = 0; b < p.length; b += 1) {
    p[b] = u[b] ^ v[b] ^ (choice === 2 ? 0xff : 0x00);
  }
  return p;
}

export async function receiverMessage(
  setup: BaseOTSetup,
  choices: Uint8Array,
  options: RunOptions = {},
): Promise<ReceiverMessageState> {
  assertAllowedCount(choices.length);
  // Own the caller's input before the first await. Otherwise a caller can
  // mutate its buffer while AES expansion is in flight and silently change the
  // public p rows, returned choices, and later verification target.
  const ownedChoices = choices.slice();
  if (setup.n !== 128 || setup.receiverKeyPairs.length !== 128) {
    throw new RangeError('the live extension requires exactly 128 base OTs');
  }
  if (ownedChoices.some((choice) => choice !== 1 && choice !== 2)) {
    throw new RangeError('every receiver choice must be 1 or 2');
  }
  checkAbort(options.signal);
  const firstIndex = reserveTransferRange(setup, ownedChoices.length);
  options.onProgress?.({ phase: 'receiver AES columns', completed: 0, total: 256 });
  const expanded = await Promise.all(
    setup.receiverKeyPairs.flatMap((pair) => [
      expandColumn(pair.zero, ownedChoices.length, firstIndex),
      expandColumn(pair.one, ownedChoices.length, firstIndex),
    ]),
  );
  checkAbort(options.signal);
  const zeroColumns = setup.receiverKeyPairs.map((_, j) => expanded[j * 2]);
  const oneColumns = setup.receiverKeyPairs.map((_, j) => expanded[j * 2 + 1]);
  const uRows = await transposeColumnsChunked(zeroColumns, ownedChoices.length, {
    signal: options.signal,
    chunkSize: WORK_CHUNK,
  });
  const vRows = await transposeColumnsChunked(oneColumns, ownedChoices.length, {
    signal: options.signal,
    chunkSize: WORK_CHUNK,
  });
  const pRows = new Uint8Array(ownedChoices.length * ROW_BYTES);
  for (let start = 0; start < ownedChoices.length; start += WORK_CHUNK) {
    const end = Math.min(ownedChoices.length, start + WORK_CHUNK);
    for (let i = start; i < end; i += 1) {
      const p = receiverPRow(rowAt(uRows, i), rowAt(vRows, i), ownedChoices[i] as 1 | 2);
      pRows.set(p, i * ROW_BYTES);
    }
    await yieldChunk(options, 'receiver message p', end, ownedChoices.length);
  }
  return { firstIndex, count: ownedChoices.length, rowBytes: ROW_BYTES, choices: ownedChoices, uRows, vRows, pRows };
}

export async function senderOutputs(
  setup: BaseOTSetup,
  receiver: ReceiverMessageState,
  options: RunOptions = {},
): Promise<SenderOutputState> {
  checkAbort(options.signal);
  options.onProgress?.({ phase: 'sender AES columns', completed: 0, total: 128 });
  const columns = await Promise.all(
    setup.senderChosenKeys.map((key) => expandColumn(key, receiver.count, receiver.firstIndex)),
  );
  const selectedRows = await transposeColumnsChunked(columns, receiver.count, {
    signal: options.signal,
    chunkSize: WORK_CHUNK,
  });
  const qRows = new Uint8Array(receiver.count * ROW_BYTES);
  const y1 = new Uint8Array(receiver.count * 32);
  const y2 = new Uint8Array(receiver.count * 32);

  for (let start = 0; start < receiver.count; start += WORK_CHUNK) {
    const end = Math.min(receiver.count, start + WORK_CHUNK);
    for (let i = start; i < end; i += 1) {
      const q = qRows.subarray(i * ROW_BYTES, (i + 1) * ROW_BYTES);
      const selected = rowAt(selectedRows, i);
      const p = rowAt(receiver.pRows, i);
      for (let b = 0; b < ROW_BYTES; b += 1) {
        q[b] = selected[b] ^ (setup.senderChoiceBytes[b] & p[b]);
      }
      const qXorR = new Uint8Array(ROW_BYTES);
      for (let b = 0; b < ROW_BYTES; b += 1) qXorR[b] = q[b] ^ setup.senderChoiceBytes[b];
      y1.set(hashRow(receiver.firstIndex + i, 1, q), i * 32);
      y2.set(hashRow(receiver.firstIndex + i, 2, qXorR), i * 32);
    }
    await yieldChunk(options, 'sender hashes', end, receiver.count);
  }
  return { qRows, y1, y2, hashCalls: receiver.count * 2 };
}

export async function receiverOutputs(
  receiver: ReceiverMessageState,
  options: RunOptions = {},
): Promise<Uint8Array> {
  const output = new Uint8Array(receiver.count * 32);
  for (let start = 0; start < receiver.count; start += WORK_CHUNK) {
    const end = Math.min(receiver.count, start + WORK_CHUNK);
    for (let i = start; i < end; i += 1) {
      output.set(
        hashRow(receiver.firstIndex + i, receiver.choices[i] as 1 | 2, rowAt(receiver.uRows, i)),
        i * 32,
      );
    }
    await yieldChunk(options, 'receiver hashes', end, receiver.count);
  }
  return output;
}

export function assertMessageBytes(messageBytes: number): void {
  if (!Number.isInteger(messageBytes) || messageBytes < 1 || messageBytes > 32) {
    throw new RangeError('Messages must contain 1 through 32 bytes; SHA-256 supplies a 32-byte mask.');
  }
}

function assertMessagePairs(messages: MessagePairs): void {
  assertMessageBytes(messages.messageBytes);
  if (messages.one.length === 0 || messages.one.length !== messages.two.length ||
      messages.one.length % messages.messageBytes !== 0) throw new RangeError('Message pair dimensions do not match');
}

export function maskMessages(messages: MessagePairs, sender: SenderOutputState): MaskedMessages {
  assertMessagePairs(messages);
  const count = messages.one.length / messages.messageBytes;
  if (sender.y1.length !== count * 32 || sender.y2.length !== count * 32) {
    throw new RangeError('sender masks and messages have different counts');
  }
  const one = new Uint8Array(messages.one.length);
  const two = new Uint8Array(messages.two.length);
  for (let i = 0; i < count; i += 1) {
    for (let b = 0; b < messages.messageBytes; b += 1) {
      one[i * messages.messageBytes + b] = messages.one[i * messages.messageBytes + b] ^ sender.y1[i * 32 + b];
      two[i * messages.messageBytes + b] = messages.two[i * messages.messageBytes + b] ^ sender.y2[i * 32 + b];
    }
  }
  // Exercise 11.17 derandomises random receiver choices. Here s_i belongs to
  // the receiver already, so direct one-time-pad masking is sufficient.
  return { one, two, messageBytes: messages.messageBytes };
}

export function unmask(
  ciphertext: Uint8Array,
  mask: Uint8Array,
  index: number,
  messageBytes = MESSAGE_BYTES,
): Uint8Array {
  assertMessageBytes(messageBytes);
  if (!Number.isInteger(index) || index < 0 || (index + 1) * messageBytes > ciphertext.length ||
      (index + 1) * 32 > mask.length) throw new RangeError('Ciphertext or mask is truncated');
  const out = new Uint8Array(messageBytes);
  for (let b = 0; b < messageBytes; b += 1) {
    out[b] = ciphertext[index * messageBytes + b] ^ mask[index * 32 + b];
  }
  return out;
}

export async function verifyAll(
  receiver: ReceiverMessageState,
  messages: MessagePairs,
  ciphertexts: MaskedMessages,
  receiverMasks: Uint8Array,
  options: RunOptions = {},
): Promise<VerifyResult> {
  assertMessagePairs(messages);
  if (messages.one.length !== receiver.count * messages.messageBytes ||
      ciphertexts.messageBytes !== messages.messageBytes || ciphertexts.one.length !== messages.one.length ||
      ciphertexts.two.length !== messages.two.length || receiverMasks.length !== receiver.count * 32) {
    throw new RangeError('Verification arrays have different dimensions');
  }
  let correctCount = 0;
  let wrongMessageRejectedCount = 0;
  for (let start = 0; start < receiver.count; start += WORK_CHUNK) {
    const end = Math.min(receiver.count, start + WORK_CHUNK);
    for (let i = start; i < end; i += 1) {
      const choseOne = receiver.choices[i] === 1;
      const chosenCipher = choseOne ? ciphertexts.one : ciphertexts.two;
      const wrongCipher = choseOne ? ciphertexts.two : ciphertexts.one;
      const chosenMessage = choseOne ? messages.one : messages.two;
      const wrongMessage = choseOne ? messages.two : messages.one;
      const got = unmask(chosenCipher, receiverMasks, i, messages.messageBytes);
      const wrong = unmask(wrongCipher, receiverMasks, i, messages.messageBytes);
      const chosenExpected = chosenMessage.subarray(
        i * messages.messageBytes,
        (i + 1) * messages.messageBytes,
      );
      const wrongExpected = wrongMessage.subarray(
        i * messages.messageBytes,
        (i + 1) * messages.messageBytes,
      );
      if (sameBytes(got, chosenExpected)) correctCount += 1;
      if (!sameBytes(wrong, wrongExpected)) wrongMessageRejectedCount += 1;
    }
    await yieldChunk(options, 'verify transfers', end, receiver.count);
  }
  return {
    count: receiver.count,
    correctCount,
    wrongMessageRejectedCount,
    allCorrect:
      correctCount === receiver.count && wrongMessageRejectedCount === receiver.count,
  };
}

export function xorRows(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new RangeError('rows must have equal length');
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i];
  return out;
}
