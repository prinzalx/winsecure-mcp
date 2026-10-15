import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/** Successful result carrying pretty-printed JSON plus a short human summary. */
export function ok(data: unknown, summary?: string): CallToolResult {
  return {
    content: [{ type: "text", text: summary ?? JSON.stringify(data, null, 2) }],
    structuredContent: { result: data },
  };
}

/** Successful result carrying plain text. */
export function text(message: string, data?: unknown): CallToolResult {
  const content = [{ type: "text" as const, text: message }];
  return data === undefined ? { content } : { content, structuredContent: { result: data } };
}

/** Failure result: the MCP layer stays happy, the model sees the problem. */
export function fail(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}
