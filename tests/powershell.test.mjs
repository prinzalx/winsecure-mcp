import assert from "node:assert/strict";
import { test } from "node:test";

import { runPowerShell } from "../dist/utils/powershell.js";

/**
 * The silent-failure fix from the live probe: on a host without Windows PowerShell (e.g. WSL), the
 * registry source must report the missing interpreter instead of reading ENOENT as "0 programs".
 */
test("runPowerShell reports a missing interpreter as an error, not as empty success", async () => {
  const saved = process.env.PATH;
  try {
    // An PATH without any directory guarantees powershell.exe cannot be resolved, on any OS.
    process.env.PATH = "C:\\__definitely_not_a_directory__";
    const res = await runPowerShell("'anything'");
    assert.equal(res.ok, false);
    assert.match(String(res.error), /not found/);
  } finally {
    process.env.PATH = saved;
  }
});
