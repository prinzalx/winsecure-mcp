import assert from "node:assert/strict";
import { test } from "node:test";
import { deflateRawSync } from "node:zlib";

import { unzip } from "../dist/utils/zip.js";

function stored(name, data) {
  return { name, data, method: 0 };
}

function deflated(name, data) {
  return { name, data, method: 8 };
}

/** Builds a minimal ZIP with one central directory entry per file. */
function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const f of files) {
    const nameBuf = Buffer.from(f.name, "utf8");
    const body = f.method === 8 ? deflateRawSync(f.data) : f.data;

    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0);
    head.writeUInt16LE(20, 4);
    head.writeUInt16LE(f.method, 8);
    head.writeUInt32LE(body.length, 18);
    head.writeUInt32LE(body.length, 22);
    head.writeUInt16LE(nameBuf.length, 26);
    locals.push(head, nameBuf, body);

    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(f.method, 10);
    cen.writeUInt32LE(body.length, 20);
    cen.writeUInt32LE(f.data.length, 24);
    cen.writeUInt16LE(nameBuf.length, 28);
    cen.writeUInt32LE(offset, 42);
    centrals.push(Buffer.concat([cen, nameBuf]));

    offset += head.length + nameBuf.length + body.length;
  }

  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, centralBuf, eocd]);
}

test("unzip reads stored and deflated entries", () => {
  const buf = buildZip([
    stored("a.txt", Buffer.from("hello")),
    deflated("dir/b.json", Buffer.from('{"ok":true}'.repeat(40))),
  ]);
  const entries = unzip(buf);
  assert.deepEqual(entries.map((e) => e.name), ["a.txt", "dir/b.json"]);
  assert.equal(entries[0].data.toString("utf8"), "hello");
  assert.equal(entries[1].data.toString("utf8"), '{"ok":true}'.repeat(40));
});

test("unzip skips directory entries", () => {
  const buf = buildZip([stored("dir/", Buffer.alloc(0)), stored("dir/f.txt", Buffer.from("x"))]);
  const entries = unzip(buf);
  assert.deepEqual(entries.map((e) => e.name), ["dir/f.txt"]);
});

test("unzip rejects a buffer that is not a zip", () => {
  assert.throws(() => unzip(Buffer.from("not a zip archive at all")), /not a zip archive/);
});
