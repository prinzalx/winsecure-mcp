import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { z } from "zod";

import type { ConfigStore } from "./config.js";
import type { DataStore } from "./store.js";
import type { Http } from "./utils/net.js";
import type { Activity } from "./dashboard.js";

export type ModuleName = "inventory" | "cves" | "todos";

/**
 * What the server can ask of the connected client.
 *
 * `sample` is the MCP sampling channel: when the client declared the `sampling` capability, the
 * server can ask the client's own model a question and get text back, which is how `assess_todo`
 * produces a verdict without the server owning an LLM. It is `undefined` for a client that cannot
 * sample, and then the fallback (an evidence package plus `save_assessment`) applies.
 */
export interface ToolContext {
  config: ConfigStore;
  store: DataStore;
  http: Http;
  clientSampling(): boolean;
  sample(prompt: string): Promise<{ text: string } | null>;
  /**
   * The server's in-memory activity ring, when the caller owns one. Since v0.6.3 a long-running
   * lookup notes per-product failures (HTTP 429/404 with the product name) into it while the call
   * still runs, which the one-line-per-call summary alone could not carry.
   */
  activity?: Activity;
}

export interface ToolDefinition {
  name: string;
  module: ModuleName;
  title: string;
  description: string;
  input: z.ZodType;
  /** Longer explanation for humans; kept out of `description`, which the model always sees. */
  docs?: string;
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<CallToolResult>;
}
