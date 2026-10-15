import assert from "node:assert/strict";
import { test } from "node:test";

import { dedupePrograms, countSources, identityScore, sameProduct } from "../dist/modules/inventory/dedupe.js";
import { isInstallerArtifact } from "../dist/modules/inventory/sources.js";

function raw(source, name, version, extra = {}) {
  return {
    source,
    name,
    version,
    publisher: null,
    install_source: null,
    package_id: null,
    path: null,
    registry_key: null,
    uninstall_string: null,
    ...extra,
  };
}

test("dedupePrograms merges the same program from three sources into one entry", () => {
  const entries = dedupePrograms(
    [
      raw("registry", "Example Tool (x64)", "1.2.3", { publisher: "Acme" }),
      raw("winget", "Example Tool", "v1.2.3", { package_id: "Acme.ExampleTool" }),
      raw("portable", "Example Tool", "1.2.3", { path: "D:\\tools\\example\\example.exe" }),
    ],
    [],
  );
  assert.equal(entries.length, 1);
  const e = entries[0];
  assert.deepEqual([...e.sources.map((s) => s.source)].sort(), ["portable", "registry", "winget"]);
  assert.deepEqual(e.package_ids, ["Acme.ExampleTool"]);
  assert.equal(e.publisher, "Acme");
  assert.equal(e.paths.length, 1);
  assert.equal(e.match_hint, "Acme.ExampleTool");
});

test("dedupePrograms keeps different versions apart and skips empty keys", () => {
  const entries = dedupePrograms(
    [raw("registry", "Tool", "1.0"), raw("registry", "Tool", "2.0"), raw("registry", "", "")],
    [],
  );
  assert.equal(entries.length, 2);
});

test("dedupePrograms preserves first_seen for a known entry", () => {
  const first = dedupePrograms([raw("registry", "Tool", "1.0")], []);
  const older = "2020-01-01T00:00:00.000Z";
  const again = dedupePrograms([raw("registry", "Tool", "1.0")], [{ ...first[0], first_seen: older }]);
  assert.equal(again[0].first_seen, older);
});

test("countSources counts per source", () => {
  const counts = countSources([
    raw("registry", "A", "1"),
    raw("registry", "B", "1"),
    raw("winget", "A", "1"),
    raw("portable", "C", "1"),
  ]);
  assert.deepEqual(counts, { registry: 2, winget: 1, portable: 1 });
});

test("identityScore ranks a package id over a display name", () => {
  const base = { name: "Example Toolbar", version: "1.0", publisher: null, sources: [], package_ids: [], paths: [], match_hint: null, first_seen: "", last_seen: "" };
  assert.equal(identityScore({ ...base, package_ids: ["Acme.ExampleToolbar"] }).confidence, "exact");
  assert.equal(identityScore({ ...base }).confidence, "high");
  assert.equal(identityScore({ ...base, version: null }).confidence, "medium");
});

test("isInstallerArtifact tags a downloaded setup outside Program Files", () => {
  assert.equal(isInstallerArtifact("C:\\Users\\user\\Documents\\npp.7.5.4.Installer.exe"), true);
  assert.equal(isInstallerArtifact("D:\\downloads\\setup_x64.exe"), true);
  // Inside Program Files the exe may legitimately be the install itself.
  assert.equal(isInstallerArtifact("C:\\Program Files\\Git\\setup.exe"), false);
  assert.equal(isInstallerArtifact("C:\\tools\\notepad.exe"), false);
  assert.equal(isInstallerArtifact(null), false);
});

test("dedupePrograms keeps an entry an artifact only while every source reports it as one", () => {
  const artifact = { installer_artifact: true };
  const onlyExe = dedupePrograms([raw("portable", "Notepad++", "7.5.4", { path: "C:\\Users\\u\\Documents\\npp.Installer.exe", ...artifact })], []);
  assert.equal(onlyExe[0].installer_artifact, true);

  const installed = dedupePrograms(
    [
      raw("portable", "Notepad++", "7.5.4", { path: "C:\\Users\\u\\Documents\\npp.Installer.exe", ...artifact }),
      raw("registry", "Notepad++", "7.5.4"),
    ],
    [],
  );
  assert.notEqual(installed[0].installer_artifact, true, "a registry hit proves the program is installed");
});

test("sameProduct tolerates small typographical distance only", () => {
  assert.ok(sameProduct("Visual Studio Code", "Visual Studio Code"));
  assert.ok(!sameProduct("Notepad++", "VLC media player"));
});
