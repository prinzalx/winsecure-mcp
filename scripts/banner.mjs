#!/usr/bin/env node
/**
 * Composes the ANSI-Shadow banner for a word, so the console logo can be regenerated instead of
 * hand-aligned. Usage: node scripts/banner.mjs WINSECURE MCP
 */
const LETTERS = {
  A: [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
  B: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
  C: [" ██████╗", "██╔════╝", "██║", "██║", "╚██████╗", " ╚═════╝"],
  D: ["██████╗ ", "██║  ██║", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
  E: ["███████╗", "██╔════╝", "█████╗", "██╔══╝", "███████╗", "╚══════╝"],
  K: ["██╗  ██╗", "██║ ██╔╝", "█████╔╝", "██╔═██╗", "██║  ██╗", "╚═╝  ╚═╝"],
  M: ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
  N: ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
  P: ["██████╗", "██╔══██╗", "██████╔╝", "██╔═══╝", "██║", "╚═╝"],
  R: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
  S: [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
  U: ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
  V: ["██╗   ██╗", "██║   ██║", "██║   ██║", "╚██╗ ██╔╝", " ╚████╔╝", "  ╚═══╝"],
  I: ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
  F: ["███████╗", "██╔════╝", "█████╗", "██╔══╝", "██║", "╚═╝"],
  T: ["████████╗", "╚══██╔══╝", "   ██║", "   ██║", "   ██║", "   ╚═╝"],
};

const words = process.argv.slice(2);
if (words.length === 0) {
  console.error("usage: node scripts/banner.mjs WORD [WORD...]");
  process.exit(1);
}

const groups = words.map((w) =>
  w
    .toUpperCase()
    .split("")
    .map((c) => LETTERS[c] ?? Array.from({ length: 6 }, () => " ")),
);

const rows = Array.from({ length: 6 }, (_, i) =>
  groups.map((g) => g.map((l) => l[i] ?? "").join(" ")).join("   "),
);

const out = rows.join("\n");
process.stdout.write(`${out}\n`);
// Column width is what decides whether a terminal wraps the logo.
process.stderr.write(`width: ${Math.max(...rows.map((r) => [...r].length))} columns\n`);
