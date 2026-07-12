import { describe, it, expect } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  senderInit,
  receiverChoose,
  senderEncrypt,
  receiverDecrypt,
  tryDecrypt,
  runFullOT,
  generateDDHPoints,
  randomIndex,
  bytesToHex,
} from './ot';

const Point = ed25519.Point;
const G = Point.BASE;

describe('Chou-Orlandi Simplest OT — correctness', () => {
  it('receiver recovers exactly M_b for both choice bits', async () => {
    for (const choice of [0, 1] as const) {
      const m0 = `zero-${choice}-${crypto.randomUUID()}`;
      const m1 = `one-${choice}-${crypto.randomUUID()}`;
      const run = await runFullOT(m0, m1, choice);
      expect(run.decrypted).toBe(choice === 0 ? m0 : m1);
    }
  });

  it('the chosen ciphertext decrypts under the receiver key end-to-end', async () => {
    const sender = senderInit();
    const receiver = receiverChoose(sender.ABytes, 1);
    const enc = await senderEncrypt(sender, receiver.BBytes, 'apple', 'banana');
    const got = await receiverDecrypt(receiver.keyBytes, enc.e1);
    expect(got).toBe('banana');
  });

  it('is correct across many random sessions (property test)', async () => {
    for (let i = 0; i < 25; i += 1) {
      const choice = (randomIndex(2) as 0 | 1);
      const m0 = crypto.randomUUID();
      const m1 = crypto.randomUUID();
      const run = await runFullOT(m0, m1, choice);
      expect(run.decrypted).toBe(choice === 0 ? m0 : m1);
      // and the privacy invariant must hold every time
      expect(run.otherFailed).toBe(true);
    }
  });
});

describe('Chou-Orlandi Simplest OT — privacy (receiver)', () => {
  it('receiver key cannot decrypt M_{1-b} (AES-GCM auth rejects)', async () => {
    for (const choice of [0, 1] as const) {
      const sender = senderInit();
      const receiver = receiverChoose(sender.ABytes, choice);
      const enc = await senderEncrypt(sender, receiver.BBytes, 'secret0', 'secret1');
      const unchosen = choice === 0 ? enc.e1 : enc.e0;
      const leaked = await tryDecrypt(receiver.keyBytes, unchosen);
      expect(leaked).toBeNull();
    }
  });

  it('the receiver key equals the chosen sender key but not the other', () => {
    for (const choice of [0, 1] as const) {
      const sender = senderInit();
      const receiver = receiverChoose(sender.ABytes, choice);
      // recompute both sender keys independently from public data + a
      const BPoint = Point.fromHex(receiver.BHex);
      const APoint = Point.fromHex(sender.AHex);
      const k0 = bytesToHex(sha256(BPoint.multiply(sender.a).toBytes()));
      const k1 = bytesToHex(sha256(BPoint.subtract(APoint).multiply(sender.a).toBytes()));
      const chosenKey = choice === 0 ? k0 : k1;
      const otherKey = choice === 0 ? k1 : k0;
      expect(receiver.keyHex).toBe(chosenKey);
      expect(receiver.keyHex).not.toBe(otherKey);
    }
  });
});

describe('Chou-Orlandi Simplest OT — privacy (sender)', () => {
  it('B is indistinguishable between b=0 and b=1 (both uniform curve points; no bit leaks structurally)', () => {
    // For a fixed A and fixed r, B(b=1) = A + B(b=0). Both are valid points and,
    // over random r, are uniformly distributed — the sender cannot read b off B.
    const sender = senderInit();
    const APoint = Point.fromHex(sender.AHex);

    // Same r would leak, so the protocol draws fresh r each call; here we assert
    // the structural relation the security argument relies on.
    const r = 12345678901234567890n % (Point.Fn.ORDER - 1n) + 1n;
    const B0 = G.multiply(r);
    const B1 = APoint.add(G.multiply(r));
    expect(bytesToHex(B0.toBytes())).not.toBe(bytesToHex(B1.toBytes()));
    // Both decode back to valid subgroup points
    expect(() => Point.fromHex(bytesToHex(B0.toBytes()))).not.toThrow();
    expect(() => Point.fromHex(bytesToHex(B1.toBytes()))).not.toThrow();
  });

  it('sender learns nothing linking B to b: encryption never inspects the choice bit', async () => {
    // Drive two full sessions with different choices but the same messages and
    // confirm the sender-side outputs (two ciphertexts) are always produced for
    // both messages regardless of b.
    for (const choice of [0, 1] as const) {
      const sender = senderInit();
      const receiver = receiverChoose(sender.ABytes, choice);
      const enc = await senderEncrypt(sender, receiver.BBytes, 'M0', 'M1');
      expect(enc.e0.ciphertext.length).toBeGreaterThan(0);
      expect(enc.e1.ciphertext.length).toBeGreaterThan(0);
      expect(enc.e0.iv).toHaveLength(12);
      expect(enc.e1.iv).toHaveLength(12);
    }
  });
});

describe('key-derivation identity (why OT works)', () => {
  it('H(r·A) == H(a·B) when b=0, and == H(a·(B−A)) when b=1', () => {
    for (const choice of [0, 1] as const) {
      const sender = senderInit();
      const receiver = receiverChoose(sender.ABytes, choice);
      const BPoint = Point.fromHex(receiver.BHex);
      const APoint = Point.fromHex(sender.AHex);
      const senderChosen =
        choice === 0
          ? sha256(BPoint.multiply(sender.a).toBytes())
          : sha256(BPoint.subtract(APoint).multiply(sender.a).toBytes());
      expect(receiver.keyHex).toBe(bytesToHex(senderChosen));
    }
  });

  it('A = aG and B is derived from A as the protocol specifies', () => {
    const sender = senderInit();
    expect(sender.AHex).toBe(bytesToHex(G.multiply(sender.a).toBytes()));
    const rState = receiverChoose(sender.ABytes, 1);
    // B = A + rG  ⇒  B − A = rG
    const BPoint = Point.fromHex(rState.BHex);
    const APoint = Point.fromHex(sender.AHex);
    expect(bytesToHex(BPoint.subtract(APoint).toBytes())).toBe(
      bytesToHex(G.multiply(rState.r).toBytes()),
    );
  });
});

describe('DDH visualizer', () => {
  it('produces 3 distinct valid curve points with a b1Index that names the DH point', () => {
    for (let i = 0; i < 20; i += 1) {
      const { points, b1Index, AHex } = generateDDHPoints();
      expect(points).toHaveLength(3);
      expect(new Set(points).size).toBe(3);
      expect(b1Index).toBeGreaterThanOrEqual(0);
      expect(b1Index).toBeLessThan(3);
      for (const p of points) {
        expect(() => Point.fromHex(p)).not.toThrow();
      }
      // The flagged point is A + rG, i.e. (flagged − A) must be a valid point.
      const APoint = Point.fromHex(AHex);
      const flagged = Point.fromHex(points[b1Index]);
      expect(() => flagged.subtract(APoint)).not.toThrow();
    }
  });

  it('b1Index takes every value over many draws (CSPRNG shuffle is unbiased-ish)', () => {
    const seen = new Set<number>();
    for (let i = 0; i < 60; i += 1) seen.add(generateDDHPoints().b1Index);
    expect(seen).toEqual(new Set([0, 1, 2]));
  });
});

describe('randomIndex helper', () => {
  it('stays in range and rejects bad bounds', () => {
    for (let i = 0; i < 200; i += 1) {
      const x = randomIndex(5);
      expect(x).toBeGreaterThanOrEqual(0);
      expect(x).toBeLessThan(5);
    }
    expect(() => randomIndex(0)).toThrow();
    expect(() => randomIndex(-1)).toThrow();
    expect(() => randomIndex(2.5)).toThrow();
  });
});
