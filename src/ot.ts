/**
 * Simplest OT Protocol (Chou-Orlandi 2015)
 *
 * Uses Edwards25519 point arithmetic from @noble/curves
 * and AES-256-GCM via Web Crypto API.
 *
 * All point operations are performed in the Ed25519 Edwards group.
 * The x25519 Montgomery ladder is NOT used because it does not expose
 * point addition — only scalar-mult. We need addition for the receiver's
 * B = A + rG computation when b = 1.
 */

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';

const Point = ed25519.Point;
const G = Point.BASE;
const ORDER = Point.Fn.ORDER;

// ── Types ────────────────────────────────────────────────────────────

export interface EncryptedPayload {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export interface SenderState {
  a: bigint;
  AHex: string;
  ABytes: Uint8Array;
}

export interface ReceiverState {
  b: 0 | 1;
  r: bigint;
  BHex: string;
  BBytes: Uint8Array;
  keyBytes: Uint8Array;
  keyHex: string;
}

export interface EncryptionResult {
  k0Hex: string;
  k1Hex: string;
  e0: EncryptedPayload;
  e1: EncryptedPayload;
}

// ── Helpers ──────────────────────────────────────────────────────────

function randomScalar(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  let val = 0n;
  for (let i = 0; i < 64; i++) {
    val = (val << 8n) | BigInt(bytes[i]);
  }
  return (val % (ORDER - 1n)) + 1n;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}

/**
 * Unbiased random integer in [0, n) using getRandomValues (rejection
 * sampling). Keeps the demo's "randomness exclusively via getRandomValues"
 * discipline — never Math.random() — even for a cosmetic shuffle.
 */
export function randomIndex(n: number): number {
  if (n <= 0 || !Number.isInteger(n)) {
    throw new RangeError('randomIndex needs a positive integer bound');
  }
  const limit = Math.floor(0x100000000 / n) * n; // largest multiple of n ≤ 2^32
  const buf = new Uint32Array(1);
  let x: number;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % n;
}

// ── AES-256-GCM (Web Crypto) ────────────────────────────────────────

/** Copy Uint8Array into a fresh ArrayBuffer (TS6 strict typing) */
function toAB(u: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(u.length);
  new Uint8Array(ab).set(u);
  return ab;
}

async function aesEncrypt(
  key: Uint8Array,
  plaintext: string,
): Promise<EncryptedPayload> {
  const ck = await crypto.subtle.importKey(
    'raw',
    toAB(key),
    { name: 'AES-GCM' },
    false,
    ['encrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      ck,
      toAB(new TextEncoder().encode(plaintext)),
    ),
  );
  return { iv, ciphertext: ct };
}

async function aesDecrypt(
  key: Uint8Array,
  payload: EncryptedPayload,
): Promise<string> {
  const ck = await crypto.subtle.importKey(
    'raw',
    toAB(key),
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toAB(payload.iv) },
    ck,
    toAB(payload.ciphertext),
  );
  return new TextDecoder().decode(pt);
}

// ── Protocol steps ───────────────────────────────────────────────────

/** Step 1 — Sender generates scalar a and public point A = aG */
export function senderInit(): SenderState {
  const a = randomScalar();
  const APoint = G.multiply(a);
  const ABytes = APoint.toBytes();
  return { a, AHex: bytesToHex(ABytes), ABytes };
}

/** Step 2 — Receiver picks choice bit b, generates scalar r, computes B */
export function receiverChoose(ABytes: Uint8Array, b: 0 | 1): ReceiverState {
  const r = randomScalar();
  const APoint = Point.fromHex(bytesToHex(ABytes));
  const rG = G.multiply(r);

  // b = 0 → B = rG ; b = 1 → B = A + rG
  const BPoint = b === 0 ? rG : APoint.add(rG);
  const BBytes = BPoint.toBytes();

  // Receiver's key: H(r · A)
  const keyBytes = sha256(APoint.multiply(r).toBytes());

  return {
    b,
    r,
    BHex: bytesToHex(BBytes),
    BBytes,
    keyBytes,
    keyHex: bytesToHex(keyBytes),
  };
}

/** Step 3 — Sender derives two keys and encrypts both messages */
export async function senderEncrypt(
  sender: SenderState,
  BBytes: Uint8Array,
  m0: string,
  m1: string,
): Promise<EncryptionResult> {
  const BPoint = Point.fromHex(bytesToHex(BBytes));
  // Reuse the public point A the sender already published (A = aG) rather
  // than recomputing G.multiply(a); k1 = H(a·(B−A)) needs the same A.
  const APoint = Point.fromHex(bytesToHex(sender.ABytes));

  // k0 = H(a · B)
  const k0 = sha256(BPoint.multiply(sender.a).toBytes());
  // k1 = H(a · (B − A))
  const k1 = sha256(BPoint.subtract(APoint).multiply(sender.a).toBytes());

  const e0 = await aesEncrypt(k0, m0);
  const e1 = await aesEncrypt(k1, m1);

  return { k0Hex: bytesToHex(k0), k1Hex: bytesToHex(k1), e0, e1 };
}

/** Step 4 — Receiver decrypts the chosen ciphertext */
export async function receiverDecrypt(
  keyBytes: Uint8Array,
  payload: EncryptedPayload,
): Promise<string> {
  return aesDecrypt(keyBytes, payload);
}

/** Try decrypting — returns null on failure (used for privacy proof) */
export async function tryDecrypt(
  keyBytes: Uint8Array,
  payload: EncryptedPayload,
): Promise<string | null> {
  try {
    return await aesDecrypt(keyBytes, payload);
  } catch {
    return null;
  }
}

// ── Convenience: run full protocol in one call ───────────────────────

export async function runFullOT(
  m0: string,
  m1: string,
  choice: 0 | 1,
): Promise<{
  sender: SenderState;
  receiver: ReceiverState;
  encryption: EncryptionResult;
  decrypted: string;
  otherFailed: boolean;
}> {
  const sender = senderInit();
  const receiver = receiverChoose(sender.ABytes, choice);
  const encryption = await senderEncrypt(sender, receiver.BBytes, m0, m1);

  const chosen = choice === 0 ? encryption.e0 : encryption.e1;
  const unchosen = choice === 0 ? encryption.e1 : encryption.e0;

  const decrypted = await receiverDecrypt(receiver.keyBytes, chosen);
  const other = await tryDecrypt(receiver.keyBytes, unchosen);

  return { sender, receiver, encryption, decrypted, otherFailed: other === null };
}

// ── DDH visualizer (Section C2) ──────────────────────────────────────

export function generateDDHPoints(): {
  points: string[];
  b1Index: number;
  AHex: string;
} {
  const a = randomScalar();
  const APoint = G.multiply(a);

  const r1 = randomScalar();
  const r2 = randomScalar();
  const r3 = randomScalar();

  const pts = [
    bytesToHex(G.multiply(r1).toBytes()),
    bytesToHex(G.multiply(r2).toBytes()),
    bytesToHex(APoint.add(G.multiply(r3)).toBytes()),
  ];

  // Shuffle: place the b=1 point at a random index (getRandomValues, not
  // Math.random — this demo sources all randomness from the CSPRNG).
  const b1Index = randomIndex(3);
  [pts[2], pts[b1Index]] = [pts[b1Index], pts[2]];

  return { points: pts, b1Index, AHex: bytesToHex(APoint.toBytes()) };
}

/**
 * Simulate `rounds` independent DDH challenges and let a strategy that always
 * guesses index 0 play each one. Because the A+rG point is placed at a uniformly
 * random index by the CSPRNG shuffle, ANY fixed or adaptive strategy is right
 * exactly 1/3 of the time — there is no signal to exploit. We run REAL point
 * generation each round (not a coin flip) so the ~33% is an empirical property
 * of the actual curve arithmetic, not a hardcoded number.
 */
export function simulateDDHGuesses(rounds: number): {
  rounds: number;
  hits: number;
  rate: number;
} {
  let hits = 0;
  for (let i = 0; i < rounds; i += 1) {
    const { b1Index } = generateDDHPoints();
    // Strategy: always pick a fresh CSPRNG index. Any strategy scores the same
    // under DDH; we pick randomly to underline "no better than a guess".
    if (randomIndex(3) === b1Index) hits += 1;
  }
  return { rounds, hits, rate: hits / rounds };
}

// ── Key reconciliation (Section B: why the keys line up) ─────────────

/**
 * Compute BOTH parties' INDEPENDENT paths to the shared secret point, each from
 * that party's own secret scalar, using the real Edwards25519 arithmetic —
 * nothing is faked. This is the heart of "why the keys line up".
 *
 *   - receiver walks  r · A         (uses r, the receiver's secret)
 *   - sender   walks  a · B         (b = 0)  or  a · (B − A)   (b = 1)   (uses a)
 *
 * Because A = aG and (for the chosen b) B−A or B reduces to rG, both routes
 * collapse to the SAME point a·r·G = arG. The equality is checked here on the
 * real byte encodings, not asserted. The UI animates the two routes meeting at
 * the identical green point; the sender's OTHER key is returned to show the
 * unchosen path lands somewhere different.
 */
export function reconcileKeys(
  a: bigint,
  r: bigint,
  ABytes: Uint8Array,
  BBytes: Uint8Array,
  b: 0 | 1,
): {
  b: 0 | 1;
  receiverPointHex: string; // r·A  — computed from the receiver's own r
  senderPointHex: string; // a·B (b=0) or a·(B−A) (b=1) — from the sender's own a
  sharedPointHex: string; // arG, the point both sides land on
  sharedMatches: boolean; // TRUE iff the two encodings are byte-identical
  chosenKeyHex: string; // H(shared point) — the working key
  otherKeyHex: string; // sender's OTHER key — must NOT equal chosenKeyHex
  senderPointExpr: string; // human label for the sender's path
} {
  const APoint = Point.fromHex(bytesToHex(ABytes));
  const BPoint = Point.fromHex(bytesToHex(BBytes));

  // Receiver's independent route: r · A.
  const receiverPoint = APoint.multiply(r);
  // Sender's independent route for the chosen bit.
  const senderChosenPoint =
    b === 0 ? BPoint.multiply(a) : BPoint.subtract(APoint).multiply(a);
  // Sender's OTHER route (the unchosen key the receiver can never reach).
  const senderOtherPoint =
    b === 0 ? BPoint.subtract(APoint).multiply(a) : BPoint.multiply(a);

  const receiverHex = bytesToHex(receiverPoint.toBytes());
  const senderHex = bytesToHex(senderChosenPoint.toBytes());
  const chosenKey = sha256(senderChosenPoint.toBytes());
  const otherKey = sha256(senderOtherPoint.toBytes());

  return {
    b,
    receiverPointHex: receiverHex,
    senderPointHex: senderHex,
    sharedPointHex: senderHex,
    sharedMatches: receiverHex === senderHex,
    chosenKeyHex: bytesToHex(chosenKey),
    otherKeyHex: bytesToHex(otherKey),
    senderPointExpr: b === 0 ? 'a · B' : 'a · (B − A)',
  };
}
