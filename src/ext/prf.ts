/** AES-128-CTR column expansion for F(k, i), using WebCrypto only. */

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.length);
  new Uint8Array(out).set(bytes);
  return out;
}

export async function aes128Ctr(
  keyBytes: Uint8Array,
  counter: Uint8Array,
  input: Uint8Array,
): Promise<Uint8Array> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('WebCrypto is unavailable; AES-128-CTR has no fallback');
  }
  if (keyBytes.length < 16) throw new RangeError('AES-128 needs at least 16 key bytes');
  if (counter.length !== 16) throw new RangeError('AES-CTR counter must be 16 bytes');
  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(keyBytes.slice(0, 16)),
    { name: 'AES-CTR' },
    false,
    ['encrypt'],
  );
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-CTR', counter: toArrayBuffer(counter), length: 128 },
      key,
      toArrayBuffer(input),
    ),
  );
}

export async function expandColumn(keyBytes: Uint8Array, bitCount: number, firstIndex = 1): Promise<Uint8Array> {
  if (!Number.isInteger(bitCount) || bitCount < 1) {
    throw new RangeError('column bit count must be a positive integer');
  }
  if (!Number.isInteger(firstIndex) || firstIndex < 1 || (firstIndex - 1) % 128 !== 0 ||
      firstIndex + bitCount - 1 > 0xffffffff) {
    throw new RangeError('AES column requires a fresh, block-aligned uint32 transfer range');
  }
  const counter = new Uint8Array(16);
  new DataView(counter.buffer).setUint32(12, (firstIndex - 1) / 128, false);
  return aes128Ctr(
    keyBytes,
    counter,
    new Uint8Array(Math.ceil(bitCount / 8)),
  );
}

export function bitAt(column: Uint8Array, index: number): 0 | 1 {
  return ((column[index >>> 3] >>> (7 - (index & 7))) & 1) as 0 | 1;
}
