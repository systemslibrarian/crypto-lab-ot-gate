import { beforeAll, describe, expect, it } from 'vitest';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '../ot';
import { setupBaseOTs, type BaseOTSetup } from './base';
import { assessCorruptAttack, makeCorruptReceiverState } from './corrupt-receiver';
import {
  createMessagePairs,
  maskMessages,
  randomChoices,
  receiverMessage,
  receiverOutputs,
  receiverPRow,
  senderOutputs,
  verifyAll,
} from './iknp';
import { aes128Ctr } from './prf';
import { rowAt, rowsToColumns, transposeColumns } from './transpose';

function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex input must have whole bytes');
  return Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

let setup: BaseOTSetup;

beforeAll(async () => {
  setup = await setupBaseOTs();
}, 120_000);

async function honestRun(count: 1_000 | 10_000 | 100_000) {
  const choices = randomChoices(count);
  const receiver = await receiverMessage(setup, choices);
  const sender = await senderOutputs(setup, receiver);
  const messages = createMessagePairs(count);
  const ciphertexts = maskMessages(messages, sender);
  const receiverMasks = await receiverOutputs(receiver);
  const verification = await verifyAll(receiver, messages, ciphertexts, receiverMasks);
  return { choices, receiver, sender, messages, ciphertexts, verification };
}

describe('128 reversed-role Chou-Orlandi setup OTs', () => {
  it('gives the extension sender exactly its r-selected transcript-salted key', () => {
    expect(setup.n).toBe(128);
    expect(setup.receiverKeyPairs).toHaveLength(128);
    expect(setup.senderChosenKeys).toHaveLength(128);
    for (let j = 0; j < 128; j += 1) {
      const selected =
        setup.senderChoiceBits[j] === 0
          ? setup.receiverKeyPairs[j].zero
          : setup.receiverKeyPairs[j].one;
      expect(bytesToHex(setup.senderChosenKeys[j])).toBe(bytesToHex(selected));
    }
  });
});

describe('IKNP-style extension correctness', () => {
  it('refuses a transfer count outside the three offered bounds', () => {
    expect(() => randomChoices(999)).toThrow('N must be one of 1,000, 10,000, or 100,000');
  });

  it('recovers every chosen message and rejects every wrong message in random N=1,000 runs', async () => {
    for (let run = 0; run < 2; run += 1) {
      const result = await honestRun(1_000);
      expect(result.verification).toEqual({
        count: 1_000,
        correctCount: 1_000,
        wrongMessageRejectedCount: 1_000,
        allCorrect: true,
      });
    }
  }, 120_000);

  it('recovers all 100,000 chosen messages in one full-size run', async () => {
    const result = await honestRun(100_000);
    expect(result.verification.correctCount).toBe(100_000);
    expect(result.verification.wrongMessageRejectedCount).toBe(100_000);
    expect(result.verification.allCorrect).toBe(true);
  }, 120_000);

  it('checks q_i = u_i or u_i xor r for every row, bit for bit', async () => {
    const { receiver, sender } = await honestRun(1_000);
    for (let i = 0; i < receiver.count; i += 1) {
      const u = rowAt(receiver.uRows, i);
      const q = rowAt(sender.qRows, i);
      const expected = u.slice();
      if (receiver.choices[i] === 2) {
        for (let b = 0; b < 16; b += 1) expected[b] ^= setup.senderChoiceBytes[b];
      }
      expect(bytesToHex(q), `q identity at transfer ${i + 1}`).toBe(bytesToHex(expected));
    }
  }, 120_000);
});

describe('matrix mechanics and sender-view distribution', () => {
  it('round-trips a 128-column transpose', () => {
    const rowCount = 257;
    const columns = Array.from({ length: 128 }, () => {
      const column = new Uint8Array(Math.ceil(rowCount / 8));
      crypto.getRandomValues(column);
      return column;
    });
    const rows = transposeColumns(columns, rowCount);
    const roundTrip = rowsToColumns(rows, rowCount, 128);
    for (let j = 0; j < 128; j += 1) {
      // Ignore padding bits after row 257; they are outside the matrix.
      for (let i = 0; i < rowCount; i += 1) {
        const mask = 1 << (7 - (i & 7));
        expect(roundTrip[j][i >>> 3] & mask).toBe(columns[j][i >>> 3] & mask);
      }
    }
  });

  it('enumerates the same p_i distribution for s=1 and s=2 at n=4', () => {
    const forOne: number[] = [];
    const forTwo: number[] = [];
    // Enumerate all 2^4 possible hidden u xor v masks (called r here in the
    // toy distribution experiment). XOR with 1111 is a permutation.
    for (let r = 0; r < 16; r += 1) {
      const u = new Uint8Array([0]);
      const v = new Uint8Array([r << 4]);
      forOne.push(receiverPRow(u, v, 1)[0] >>> 4);
      forTwo.push((receiverPRow(u, v, 2)[0] >>> 4) & 0xf);
    }
    expect(forOne.sort((a, b) => a - b)).toEqual(forTwo.sort((a, b) => a - b));
    expect(forOne).toEqual(Array.from({ length: 16 }, (_, i) => i));
  });
});

describe('deliberately broken corrupt-receiver mode', () => {
  it('equation 23.23 recovers the exact sender r and both later messages', async () => {
    const choices = randomChoices(1_000);
    choices.fill(1, 0, 128);
    const honest = await receiverMessage(setup, choices);
    const corrupt = makeCorruptReceiverState(honest);
    const sender = await senderOutputs(setup, corrupt);
    const messages = createMessagePairs(1_000);
    const ciphertexts = maskMessages(messages, sender);
    const attack = await assessCorruptAttack(setup, corrupt, sender, ciphertexts, messages);
    expect(bytesToHex(attack.recovered.bits)).toBe(bytesToHex(setup.senderChoiceBits));
    expect(attack.recoveredExactly).toBe(true);
    expect(attack.chosenCorrectCount).toBe(1_000);
    expect(attack.bothMessagesRecoveredCount).toBe(872);
  }, 120_000);
});

describe('published primitive known-answer vectors', () => {
  it('matches all four blocks of NIST SP 800-38A F.5.1 CTR-AES128.Encrypt', async () => {
    const key = fromHex('2b7e151628aed2a6abf7158809cf4f3c');
    const counter = fromHex('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
    const plaintext = fromHex(
      '6bc1bee22e409f96e93d7e117393172a' +
        'ae2d8a571e03ac9c9eb76fac45af8e51' +
        '30c81c46a35ce411e5fbc1191a0a52ef' +
        'f69f2445df4f9b17ad2b417be66c3710',
    );
    const expected =
      '874d6191b620e3261bef6864990db6ce' +
      '9806f66b7970fdff8617187bb9fffdff' +
      '5ae4df3edbd5d35e5b4f09020db03eab' +
      '1e031dda2fbe03d1792170a0f3009cee';
    expect(bytesToHex(await aes128Ctr(key, counter, plaintext))).toBe(expected);
  });

  it('matches NIST CAVP SHA256LongMsg vector 1 (1,304 bits, over two blocks)', () => {
    const message = fromHex(
      '451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae08' +
        '6b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b8' +
        '5c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c' +
        '19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac419' +
        '8007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec',
    );
    expect(message).toHaveLength(163);
    expect(bytesToHex(sha256(message))).toBe(
      '3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2',
    );
  });
});
