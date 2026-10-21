import { bitAt } from './prf';

/**
 * Transpose n AES-expanded columns into packed row-major vectors.
 * For the live protocol n=128, so each row occupies exactly 16 bytes.
 */
export function transposeColumns(
  columns: Uint8Array[],
  rowCount: number,
): Uint8Array {
  if (columns.length < 1 || columns.length % 8 !== 0) {
    throw new RangeError('column count must be a positive multiple of eight');
  }
  const rowBytes = columns.length / 8;
  const rows = new Uint8Array(rowCount * rowBytes);
  for (let row = 0; row < rowCount; row += 1) {
    const rowOffset = row * rowBytes;
    for (let column = 0; column < columns.length; column += 1) {
      if (bitAt(columns[column], row) === 1) {
        rows[rowOffset + (column >>> 3)] |= 1 << (7 - (column & 7));
      }
    }
  }
  return rows;
}

export async function transposeColumnsChunked(
  columns: Uint8Array[],
  rowCount: number,
  options: { signal?: AbortSignal; chunkSize?: number } = {},
): Promise<Uint8Array> {
  if (columns.length < 1 || columns.length % 8 !== 0) {
    throw new RangeError('column count must be a positive multiple of eight');
  }
  const rowBytes = columns.length / 8;
  const rows = new Uint8Array(rowCount * rowBytes);
  const chunkSize = options.chunkSize ?? 4096;
  for (let start = 0; start < rowCount; start += chunkSize) {
    if (options.signal?.aborted) throw new DOMException('OT extension cancelled', 'AbortError');
    const end = Math.min(rowCount, start + chunkSize);
    for (let row = start; row < end; row += 1) {
      const rowOffset = row * rowBytes;
      for (let column = 0; column < columns.length; column += 1) {
        if (bitAt(columns[column], row) === 1) {
          rows[rowOffset + (column >>> 3)] |= 1 << (7 - (column & 7));
        }
      }
    }
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
  }
  return rows;
}

export function rowAt(rows: Uint8Array, row: number, rowBytes = 16): Uint8Array {
  return rows.subarray(row * rowBytes, (row + 1) * rowBytes);
}

export function rowsToColumns(
  rows: Uint8Array,
  rowCount: number,
  columnCount: number,
): Uint8Array[] {
  const rowBytes = columnCount / 8;
  if (!Number.isInteger(rowBytes) || rows.length !== rowCount * rowBytes) {
    throw new RangeError('packed row dimensions do not match');
  }
  const columns = Array.from(
    { length: columnCount },
    () => new Uint8Array(Math.ceil(rowCount / 8)),
  );
  for (let row = 0; row < rowCount; row += 1) {
    for (let column = 0; column < columnCount; column += 1) {
      const value = (rows[row * rowBytes + (column >>> 3)] >>> (7 - (column & 7))) & 1;
      if (value === 1) columns[column][row >>> 3] |= 1 << (7 - (row & 7));
    }
  }
  return columns;
}
