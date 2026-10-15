// Regenerates the ASCII banner for src/index.ts and README.md.
//
// The letters are drawn on a strict 5-row grid of full-block cells, so every
// column has exactly the same width in any monospace renderer. Earlier
// versions used shadow/half-block box-drawing art, which drifted out of
// alignment in GitHub's narrow fenced panel (the leading "W" got clipped).
//
//   node scripts/banner.mjs

const ROWS = 5;

const LETTERS = {
  " ": ["     ", "     ", "     ", "     ", "     "],
  A: [" ███ ", "█   █", "█████", "█   █", "█   █"],
  C: [" ████", "█    ", "█    ", "█    ", " ████"],
  E: ["█████", "█    ", "████ ", "█    ", "█████"],
  I: ["███", " █ ", " █ ", " █ ", "███"],
  N: ["█   █", "██  █", "█ █ █", "█  ██", "█   █"],
  R: ["████ ", "█   █", "████ ", "█ █  ", "█  ██"],
  S: ["█████", "█    ", " ███ ", "    █", "█████"],
  U: ["█   █", "█   █", "█   █", "█   █", " ███ "],
  W: ["█     █", "█     █", "█  █  █", "█ █ █ █", " ██ ██ "],
};

export function banner(text) {
  const out = [];
  for (let row = 0; row < ROWS; row += 1) {
    out.push(
      text
        .split("")
        .map((ch) => LETTERS[ch][row])
        .join(" "),
    );
  }
  return out.join("\n");
}

if (process.argv[1] && process.argv[1].endsWith("banner.mjs")) {
  console.log(banner("WINSECURE"));
}
