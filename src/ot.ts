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
  const APoint = G.multiply(sender.a);

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

  // Shuffle: place the b=1 point at a random index
  const b1Index = Math.floor(Math.random() * 3);
  [pts[2], pts[b1Index]] = [pts[b1Index], pts[2]];

  return { points: pts, b1Index, AHex: bytesToHex(APoint.toBytes()) };
}
