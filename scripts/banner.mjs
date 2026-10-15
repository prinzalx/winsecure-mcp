// Regenerates the ASCII banner for src/index.ts and README.md.
//
// The glyphs are the ANSI Shadow font (the six-row box-drawing style winadmin-mcp uses: full
// blocks with a ╗/═ shadow edge), so the two servers show the same bold logo look in the
// console. Each glyph carries its own padding and the rows are joined without a separator,
// exactly like figlet renders the font.
//
//   node scripts/banner.mjs

const ROWS = 6;

const LETTERS = {
  " ": ["   ", "   ", "   ", "   ", "   ", "   "],
  C: [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
  E: ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
  I: ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
  M: ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
  N: ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
  P: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
  R: ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
  S: ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
  U: ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
  W: ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
};

export function banner(text) {
  const out = [];
  for (let row = 0; row < ROWS; row += 1) {
    out.push(
      text
        .split("")
        .map((ch) => LETTERS[ch][row])
        .join(""),
    );
  }
  return out.join("\n");
}

if (process.argv[1] && process.argv[1].endsWith("banner.mjs")) {
  console.log(banner("WINSECURE MCP"));
}
