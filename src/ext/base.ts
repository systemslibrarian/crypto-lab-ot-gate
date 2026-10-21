/**
 * The 128 public-key OTs used once by the extension setup.
 *
 * Roles are intentionally reversed: the extension receiver is the base-OT
 * sender and gets both keys; the extension sender chooses r_j and gets one.
 * The existing teaching engine remains untouched. We reuse its public setup
 * and choice operations, but derive fresh extension keys with Chou-Orlandi's
 * typed transcript KDF H(A || B || j || point).
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomIndex, receiverChoose, senderInit } from '../ot';

const Point = ed25519.Point;

export interface BaseKeyPair {
  zero: Uint8Array;
  one: Uint8Array;
}

export interface BaseOTSetup {
  n: number;
  receiverKeyPairs: BaseKeyPair[];
  senderChoiceBits: Uint8Array;
  senderChosenKeys: Uint8Array[];
  senderChoiceBytes: Uint8Array;
  elapsedMs: number;
}

// A setup can serve many batches, but never the same PRF/hash positions twice.
// Keep reservations outside the displayed key material; a cancelled batch also
// consumes its range. Both parties are simulated against this same setup object.
const uses = new WeakMap<BaseOTSetup, { nextIndex: number; compromised: boolean }>();

export function reserveTransferRange(setup: BaseOTSetup, count: number): number {
  const state = uses.get(setup);
  if (!state || state.compromised) throw new Error('Base setup is unavailable or compromised; run 128 fresh base OTs.');
  if (!Number.isInteger(count) || count < 1 || count > 100_000) throw new RangeError('invalid batch size');
  const firstIndex = state.nextIndex;
  if (firstIndex + count - 1 > 0xffffffff) throw new RangeError('Transfer indices exhausted; run fresh base OTs.');
  // Start on an AES block boundary. Unused padding bits are burned, not reused.
  state.nextIndex = firstIndex + Math.ceil(count / 128) * 128;
  return firstIndex;
}

export function markBaseSetupCompromised(setup: BaseOTSetup): void {
  const state = uses.get(setup);
  if (!state) throw new Error('Unknown base setup');
  state.compromised = true;
}

export function isBaseSetupCompromised(setup: BaseOTSetup): boolean {
  return uses.get(setup)?.compromised ?? true;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function indexBytes(index: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, index, false);
  return out;
}

export function transcriptKdf(
  A: Uint8Array,
  B: Uint8Array,
  index: number,
  point: Uint8Array,
): Uint8Array {
  return sha256(concatBytes(A, B, indexBytes(index), point));
}

export function packChoiceBits(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i += 1) {
    if (bits[i] === 1) out[i >>> 3] |= 1 << (7 - (i & 7));
  }
  return out;
}

export async function setupBaseOTs(n = 128): Promise<BaseOTSetup> {
  if (!Number.isInteger(n) || n < 1 || n > 128) {
    throw new RangeError('base OT count must be an integer from 1 through 128');
  }

  const started = performance.now();
  const receiverKeyPairs: BaseKeyPair[] = [];
  const senderChoiceBits = new Uint8Array(n);
  const senderChosenKeys: Uint8Array[] = [];

  for (let j = 0; j < n; j += 1) {
    const baseSender = senderInit();
    const choice = randomIndex(2) as 0 | 1;
    const baseReceiver = receiverChoose(baseSender.ABytes, choice);
    const APoint = Point.fromHex(bytesToHex(baseSender.ABytes));
    const BPoint = Point.fromHex(bytesToHex(baseReceiver.BBytes));

    // Same Chou-Orlandi point formulas as senderEncrypt(), now with the
    // transcript and one-based setup index included in the typed KDF.
    const k0 = transcriptKdf(
      baseSender.ABytes,
      baseReceiver.BBytes,
      j + 1,
      BPoint.multiply(baseSender.a).toBytes(),
    );
    const k1 = transcriptKdf(
      baseSender.ABytes,
      baseReceiver.BBytes,
      j + 1,
      BPoint.subtract(APoint).multiply(baseSender.a).toBytes(),
    );
    const chosen = transcriptKdf(
      baseSender.ABytes,
      baseReceiver.BBytes,
      j + 1,
      APoint.multiply(baseReceiver.r).toBytes(),
    );

    receiverKeyPairs.push({ zero: k0, one: k1 });
    senderChoiceBits[j] = choice;
    senderChosenKeys.push(chosen);

    if (bytesToHex(chosen) !== bytesToHex(choice === 0 ? k0 : k1)) {
      throw new Error(`base OT ${j + 1} produced inconsistent transcript keys`);
    }
  }

  const setup: BaseOTSetup = {
    n,
    receiverKeyPairs,
    senderChoiceBits,
    senderChosenKeys,
    senderChoiceBytes: packChoiceBits(senderChoiceBits),
    elapsedMs: performance.now() - started,
  };
  uses.set(setup, { nextIndex: 1, compromised: false });
  return setup;
}
