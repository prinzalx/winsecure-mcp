import assert from "node:assert/strict";
import { test } from "node:test";

import { normName, normVersion, dedupKey, compareVersions, similarity, severityBand } from "../dist/utils/matching.js";

test("normName drops arch and locale markers", () => {
  assert.equal(normName("Example Toolbar (x64)"), "example toolbar");
  assert.equal(normName("Example Toolbar (de-DE)"), "example toolbar");
  assert.equal(normName("Example Toolbar 64-bit"), "example toolbar");
});

test("normName keeps digits and special chars so products stay distinguishable", () => {
  assert.notEqual(normName("Visual Studio 2022"), normName("Visual Studio"));
  assert.ok(normName("Notepad++").includes("notepad++"));
});

test("normName drops noise words and version suffixes", () => {
  assert.equal(normName("Acme Runtime Tools version: 1.2.3"), "acme");
  assert.equal(normName(""), "");
  assert.equal(normName(null), "");
  assert.equal(normName(undefined), "");
});

test("normVersion strips range markers, leading v and trailing comments", () => {
  assert.equal(normVersion(">= 1.2.3"), "1.2.3");
  assert.equal(normVersion("<1.2.3"), "1.2.3");
  assert.equal(normVersion("v14.40.33810"), "14.40.33810");
  assert.equal(normVersion("1.2.3 (build 99)"), "1.2.3");
  assert.equal(normVersion(" 1.2.3 "), "1.2.3");
});

test("dedupKey unifies the same program across sources", () => {
  const a = dedupKey("Example Toolbar (x64)", "1.2.3");
  const b = dedupKey("Example Toolbar 64-bit ", "v1.2.3");
  assert.equal(a, b);
  assert.notEqual(a, dedupKey("Example Toolbar", "1.2.4"));
});

test("compareVersions orders dotted numeric versions", () => {
  assert.ok(compareVersions("1.2.3", "1.2.10") < 0);
  assert.ok(compareVersions("1.10", "1.9") > 0);
  assert.equal(compareVersions("1.2", "1.2.0"), 0);
  assert.ok(compareVersions("2.0", "v1.9.9") > 0);
});

test("similarity is 1 for equal names and degrades with distance", () => {
  assert.equal(similarity("7-Zip", "7-Zip"), 1);
  assert.ok(similarity("7-Zip", "7zip") >= 0.75);
  assert.ok(similarity("Visual Studio Code", "Visual Studio Cod") >= 0.9);
  // Unrelated products must stay below the sameProduct threshold of 0.88.
  assert.ok(similarity("Notepad++", "VLC media player") < 0.88);
  assert.ok(similarity("Notepad++", "Paint") < 0.88);
  assert.equal(similarity("", "anything"), 0);
});

test("severityBand maps scores to english labels", () => {
  assert.equal(severityBand(null), "none");
  assert.equal(severityBand(0), "none");
  assert.equal(severityBand(3.9), "low");
  assert.equal(severityBand(4), "medium");
  assert.equal(severityBand(7), "high");
  assert.equal(severityBand(9), "critical");
  assert.equal(severityBand(Number.NaN), "none");
});
