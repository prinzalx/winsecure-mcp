import type { ModuleName, ToolDefinition } from "../types.js";

import { cveTools } from "./cves/index.js";
import { inventoryTools } from "./inventory/index.js";
import { todoTools } from "./todos/index.js";

/** Every tool the server knows about, in the order the documentation lists them. */
export const ALL_TOOLS: ToolDefinition[] = [...inventoryTools, ...cveTools, ...todoTools];

export const TOOLS_BY_NAME: Map<string, ToolDefinition> = new Map(ALL_TOOLS.map((t) => [t.name, t]));

/** One paragraph per module, for the docs and the tool listing. */
export const MODULE_DOCS: Record<ModuleName, string> = {
  inventory:
    "The installed-software inventory: the Uninstall registry keys, `winget list` and a portable .exe walk, merged " +
    "under a normalised (product, version) key so each program appears exactly once with every source listed.",
  cves:
    "Matching that inventory against the CVE sources. cvelistV5 supplies the CVE records, CISA KEV marks what is " +
    "actively exploited, EPSS prioritises, and NVD answers a single CVE detail. Everything is cached on disk, so a " +
    "run never depends on the network.",
  todos: "The work list: CVE findings as persistent to-dos, sorted by exploitation and severity, each with an effort assessment on the four axes.",
};
