#!/usr/bin/env node
/**
 * Guards the dashboard's own JavaScript. `webui.html` is shipped verbatim to the browser, so a
 * TypeScript annotation or other non-JS syntax inside its <script> block silently kills the whole
 * page there (it renders empty, only "loading…" stays) while every test and the API stay green.
 * Parsing the block as an async function body is what the browser effectively does (top-level
 * await is used), so this test fails when the dashboard would break in the field.
 *
 * Usage: node scripts/webui-syntax-check.mjs
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;

for (const file of ["../src/webui.html", "../dist/webui.html"]) {
  const html = readFileSync(fileURLToPath(new URL(file, import.meta.url)), "utf8");
  const match = /<script>([\s\S]*?)<\/script>/.exec(html);
  if (!match) {
    console.error(`${file}: no <script> block found`);
    process.exit(1);
  }
  try {
    new AsyncFunction(match[1]);
    console.log(`${file}: dashboard JS parses`);
  } catch (cause) {
    console.error(`${file}: SYNTAX ERROR — ${String(cause.message)}`);
    process.exit(1);
  }
}
