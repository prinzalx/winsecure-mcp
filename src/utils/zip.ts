import { inflateRawSync } from "node:zlib";

/**
 * Minimal read-only ZIP reader over a Buffer.
 *
 * cvelistV5 ships its bulk as a ZIP of one JSON file per CVE, and a full unzip library for a single
 * read call is not worth the dependency. Only stored and deflate entries are supported, which is
 * all the ZIP format needs for the assets this server reads.
 */
export interface ZipEntry {
  name: string;
  data: Buffer;
}

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;

export function unzip(buf: Buffer): ZipEntry[] {
  const eocd = findEndOfCentralDirectory(buf);
  if (eocd < 0) {
    throw new Error("not a zip archive: end of central directory not found");
  }

  const count = buf.readUInt16LE(eocd + 10);
  let offset = buf.readUInt32LE(eocd + 16);
  const entries: ZipEntry[] = [];

  for (let i = 0; i < count; i += 1) {
    if (offset + 46 > buf.length || buf.readUInt32LE(offset) !== CENTRAL_HEADER) break;

    const method = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const nameLength = buf.readUInt16LE(offset + 28);
    const extraLength = buf.readUInt16LE(offset + 30);
    const commentLength = buf.readUInt16LE(offset + 32);
    const localOffset = buf.readUInt32LE(offset + 42);
    const name = buf.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");

    offset += 46 + nameLength + extraLength + commentLength;
    if (name.endsWith("/")) continue;

    const data = readLocal(buf, localOffset, nameLength, method, compressedSize);
    if (data) entries.push({ name, data });
  }

  return entries;
}

function readLocal(
  buf: Buffer,
  localOffset: number,
  _nameLength: number,
  method: number,
  compressedSize: number,
): Buffer | null {
  if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== LOCAL_HEADER) return null;
  const nameLen = buf.readUInt16LE(localOffset + 26);
  const extraLen = buf.readUInt16LE(localOffset + 28);
  const start = localOffset + 30 + nameLen + extraLen;
  const raw = buf.subarray(start, start + compressedSize);

  if (method === 0) return Buffer.from(raw);
  if (method === 8) {
    try {
      return inflateRawSync(raw);
    } catch {
      return null;
    }
  }
  return null;
}

function findEndOfCentralDirectory(buf: Buffer): number {
  const min = Math.max(0, buf.length - 22 - 65536);
  for (let i = buf.length - 22; i >= min; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) return i;
  }
  return -1;
}
