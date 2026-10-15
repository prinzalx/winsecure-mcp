#!/usr/bin/env node
import { copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
copyFileSync(`${root}src/webui.html`, `${root}dist/webui.html`);
process.stdout.write("copied webui.html to dist/\n");
