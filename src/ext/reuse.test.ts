import { createCipheriv, createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { isBaseSetupCompromised, setupBaseOTs } from './base';
import { assessCorruptAttack, decryptBoth, makeCorruptReceiverState } from './corrupt-receiver';
import { createMessagePairs, hashRow, maskMessages, randomChoices, receiverMessage, receiverOutputs, senderOutputs, unmask, verifyAll } from './iknp';
import { expandColumn } from './prf';
import { rowAt } from './transpose';

describe('fresh transfer positions under a reusable base setup', () => {
  it('uses disjoint PRF positions and globally indexed hashes in consecutive honest batches', async () => {
    const setup = await setupBaseOTs();
    const choices = randomChoices(1000);
    const first = await receiverMessage(setup, choices);
    const secondChoices = choices.map((s) => s === 1 ? 2 : 1);
    const second = await receiverMessage(setup, secondChoices);
    expect(first.firstIndex).toBe(1);
    expect(second.firstIndex).toBe(1025);

    // A sender formerly read choice changes from p_old XOR p_new: each row
    // was all 00 or FF. A new PRF range removes that repeated mask entirely.
    let exposedChangeRows = 0;
    for (let i = 0; i < 1000; i++) {
      const difference = rowAt(first.pRows, i).map((byte, j) => byte ^ rowAt(second.pRows, i)[j]);
      if (difference.every((byte) => byte === 0xff)) exposedChangeRows++;
    }
    expect(exposedChangeRows).toBe(0);

    // Independent Node AES implementation: batch two starts at AES block 8,
    // after all 1,024 bits (including padding) reserved by batch one.
    const counter = Buffer.alloc(16);
    counter.writeUInt32BE(8, 12);
    const cipher = createCipheriv('aes-128-ctr', setup.receiverKeyPairs[0].zero.subarray(0, 16), counter);
    const expectedColumn = Buffer.concat([cipher.update(Buffer.alloc(125)), cipher.final()]);
    const actualColumn = await expandColumn(setup.receiverKeyPairs[0].zero, 1000, second.firstIndex);
    expect(Buffer.from(actualColumn)).toEqual(expectedColumn);
    for (let i = 0; i < 1000; i++) {
      expect((rowAt(second.uRows, i)[0] >>> 7) & 1).toBe((expectedColumn[i >>> 3] >>> (7 - (i & 7))) & 1);
    }

    const sender = await senderOutputs(setup, second);
    const masks = await receiverOutputs(second);
    for (const i of [0, 127, 999]) {
      const prefix = Buffer.alloc(5);
      prefix.writeUInt32BE(second.firstIndex + i, 0);
      prefix[4] = second.choices[i];
      const expected = createHash('sha256').update(prefix).update(rowAt(second.uRows, i)).digest();
      expect(Buffer.from(masks.subarray(i * 32, (i + 1) * 32))).toEqual(expected);
      const selected = second.choices[i] === 1 ? sender.y1 : sender.y2;
      expect(Buffer.from(selected.subarray(i * 32, (i + 1) * 32))).toEqual(expected);
    }
    const messages = createMessagePairs(1000);
    const result = await verifyAll(second, messages, maskMessages(messages, sender), masks);
    expect(result.correctCount).toBe(1000);
    expect(result.wrongMessageRejectedCount).toBe(1000);
  });

  it('reserves concurrent batches before either asynchronous expansion completes', async () => {
    const setup = await setupBaseOTs();
    const batches = await Promise.all([
      receiverMessage(setup, randomChoices(1000)),
      receiverMessage(setup, randomChoices(10000)),
    ]);
    expect(batches[1].firstIndex).toBeGreaterThan(batches[0].firstIndex + batches[0].count - 1);
  });

  it('burns the range of a cancelled batch instead of handing it to the next run', async () => {
    const setup = await setupBaseOTs();
    const controller = new AbortController();
    await expect(receiverMessage(setup, randomChoices(1000), {
      signal: controller.signal,
      onProgress: () => controller.abort(),
    })).rejects.toMatchObject({ name: 'AbortError' });
    const next = await receiverMessage(setup, randomChoices(1000));
    expect(next.firstIndex).toBe(1025);
  });

  it('retires compromised base correlations and an old recovered r cannot open a fresh setup', async () => {
    const setup = await setupBaseOTs();
    const receiver = makeCorruptReceiverState(await receiverMessage(setup, randomChoices(1000)));
    const sender = await senderOutputs(setup, receiver);
    const messages = createMessagePairs(1000);
    const attack = await assessCorruptAttack(setup, receiver, sender, maskMessages(messages, sender), messages);
    expect(attack.recoveredExactly).toBe(true);
    expect(attack.bothMessagesRecoveredCount).toBe(872);
    expect(isBaseSetupCompromised(setup)).toBe(true);
    await expect(receiverMessage(setup, randomChoices(1000))).rejects.toThrow(/compromised/);
    const fresh = await setupBaseOTs();
    const honest = await receiverMessage(fresh, randomChoices(1000));
    const honestSender = await senderOutputs(fresh, honest);
    expect(await decryptBoth(honest, attack.recovered, maskMessages(messages, honestSender), messages)).toBe(0);
    expect(isBaseSetupCompromised(fresh)).toBe(false);
  });
});

describe('bounded message masks and index encodings', () => {
  it.each([0, -1, 0.5, 33, 40, NaN, Infinity])('refuses message size %s before producing ciphertext', (size) => {
    expect(() => createMessagePairs(1000, size)).toThrow(/1 through 32/);
    const forgedPair = { one: new Uint8Array(40000), two: new Uint8Array(40000), messageBytes: size };
    const sender = { qRows: new Uint8Array(), y1: new Uint8Array(32000), y2: new Uint8Array(32000), hashCalls: 2000 };
    expect(() => maskMessages(forgedPair, sender)).toThrow(/1 through 32/);
    expect(() => unmask(new Uint8Array(40000), sender.y1, 999, size)).toThrow(/1 through 32/);
  });

  it('round-trips every byte at the full 32-byte mask boundary', async () => {
    const setup = await setupBaseOTs();
    const receiver = await receiverMessage(setup, randomChoices(1000));
    const sender = await senderOutputs(setup, receiver);
    const messages = createMessagePairs(1000, 32);
    const encrypted = maskMessages(messages, sender);
    const masks = await receiverOutputs(receiver);
    expect((await verifyAll(receiver, messages, encrypted, masks)).allCorrect).toBe(true);
    expect(() => maskMessages({ ...messages, two: messages.two.subarray(1) }, sender)).toThrow(/dimensions/);
    expect(() => unmask(encrypted.one.subarray(1), masks, 999, 32)).toThrow(/truncated/);
    expect(() => unmask(encrypted.one, masks.subarray(1), 999, 32)).toThrow(/truncated/);
    await expect(verifyAll(receiver, messages, { ...encrypted, two: encrypted.two.subarray(1) }, masks)).rejects.toThrow(/dimensions/);
  });

  it.each([0, -1, 1.5, 0x100000000, NaN])('refuses a wrapping or invalid hash index %s', (index) => {
    expect(() => hashRow(index, 1, new Uint8Array(16))).toThrow(/uint32/);
  });
});
