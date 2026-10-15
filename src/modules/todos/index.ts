import { z } from "zod";

import type { ToolDefinition } from "../../types.js";
import { fail, ok } from "../../utils/result.js";
import { ASSESSMENT_PROMPT_RULES, ASSESSMENT_SCHEMA, buildEvidence, normalizeAssessment, severityRank } from "./todo.js";
import type { Todo } from "../../model.js";

const CONFIDENCES = ["exact", "high", "medium", "low"] as const;

/** Compact line form used by `list_todos`, so the model sees a table and not a JSON wall. */
function summarize(todos: Todo[]): string {
  if (todos.length === 0) return "No open todos";
  return todos
    .slice(0, 40)
    .map((t) => {
      const flag = t.any_kev ? "KEV" : "   ";
      const assessed = t.assessment ? "assessed" : "open";
      return `${t.id}  ${flag}  ${t.max_severity.padEnd(8)}  cvss ${fmt(t.max_cvss)}  epss ${fmt(t.max_epss)}  ${String(t.cves.length).padStart(3)} CVE  ${t.match_confidence.padEnd(6)}  ${assessed}  ${t.program} ${t.version ?? ""}`;
    })
    .join("\n");
}

function fmt(n: number | null): string {
  return n === null ? " -  " : n.toFixed(2).padStart(5);
}

function findTodo(store: { todos: Todo[] }, id: string): Todo | undefined {
  return store.todos.find((t) => t.id === id);
}

export const todoTools: ToolDefinition[] = [
  {
    name: "list_todos",
    module: "todos",
    title: "List to-dos",
    description:
      "The CVE to-do list, sorted KEV first, then severity, then EPSS. Filterable by status.",
    docs:
      "The list the human works from. Every entry names the program, its version, how many CVEs back it, whether CISA " +
      "KEV marks it as actively exploited, and the assessment status.\n" +
      "Sort order is deliberate: an actively exploited finding outranks a merely high CVSS, because that is the signal " +
      "that says patch this one first.\n" +
      "An empty list after check_cves is an answer, not a failure: it means no CVE matched the installed programs.",
    input: z.object({
      status: z.enum(["open", "assessed", "dismissed", "all"]).optional().describe("Filter by status. Defaults to all non-dismissed"),
      kev_only: z.boolean().optional().describe("Only entries with at least one actively exploited CVE"),
      limit: z.number().int().positive().max(200).optional().describe("Maximum entries. Defaults to 40"),
    }),
    handler: async (args, ctx) => {
      const store = ctx.store.load();
      const statusFilter = String(args.status ?? "active");

      let todos = store.todos;
      if (statusFilter === "open" || statusFilter === "assessed" || statusFilter === "dismissed") {
        todos = todos.filter((t) => t.status === statusFilter);
      } else {
        todos = todos.filter((t) => t.status !== "dismissed");
      }
      if (args.kev_only === true) todos = todos.filter((t) => t.any_kev);

      todos = [...todos].sort(
        (a, b) =>
          Number(b.any_kev) - Number(a.any_kev) ||
          severityRank(b.max_severity) - severityRank(a.max_severity) ||
          (b.max_cvss ?? 0) - (a.max_cvss ?? 0) ||
          (b.max_epss ?? 0) - (a.max_epss ?? 0) ||
          a.program.localeCompare(b.program, "en"),
      );

      const limit = typeof args.limit === "number" ? args.limit : 40;
      const shown = todos.slice(0, limit);

      return ok(
        { count: todos.length, shown: shown.length, todos: shown },
        `${summarize(shown)}${todos.length > shown.length ? `\n…and ${String(todos.length - shown.length)} more` : ""}`,
      );
    },
  },
  {
    name: "assess_todo",
    module: "todos",
    title: "Assess to-do",
    description:
      "Effort assessment for one to-do on axes a-d. With a sampling-capable client the server asks it directly and stores the verdict; otherwise it returns an evidence package for `save_assessment`.",
    docs:
      "The server owns no LLM, so the assessment comes from the client. When the client declared the MCP sampling " +
      "capability during the handshake, the server sends the evidence and the schema as a sampling request, parses the " +
      "answer, and stores it itself — one call and the verdict is in the ToDo list.\n" +
      "Without sampling the same evidence and the same schema come back as data, the client reasons over them, and " +
      "writes the result through save_assessment. Both paths produce exactly the same stored shape.\n" +
      "The four axes are fixed: (a) plain .exe swap, (b) a new vendor setup needed, (c) breaking change expected, " +
      "(d) only a part program of a suite affected — named in affected_part.",
    input: z.object({
      todo_id: z.string().min(1).describe("The id from list_todos"),
    }),
    handler: async (args, ctx) => {
      const store = ctx.store.load();
      const todo = findTodo(store, String(args.todo_id));
      if (!todo) return fail(`Unknown todo_id "${String(args.todo_id)}"`);

      const entry = store.inventory.find((e) => e.id === todo.inventory_id);
      const evidence = buildEvidence(todo, entry);

      if (!ctx.clientSampling()) {
        return ok(
          { mode: "evidence_package", evidence, schema: ASSESSMENT_SCHEMA, next: "save_assessment" },
          `${todo.program} ${todo.version ?? ""}: client cannot sample, so the evidence package is returned. Assess it and call save_assessment.`,
        );
      }

      const prompt =
        `You are assessing the patch effort for one Windows program in a CVE to-do list.\n` +
        `Program: ${todo.program} ${todo.version ?? "(version unknown)"}\n` +
        `Publisher: ${todo.publisher ?? "unknown"}\n` +
        `Install sources: ${evidence.install_sources.join(", ") || "unknown"}\n` +
        `Package ids: ${evidence.package_ids.join(", ") || "none"}\n` +
        `CVEs: ${String(evidence.cve_count)} (${evidence.kev_cves.length} actively exploited)\n` +
        `Severity: ${evidence.max_severity}${evidence.max_cvss !== null ? ` (CVSS ${String(evidence.max_cvss)})` : ""}${evidence.max_epss !== null ? `, EPSS ${String(evidence.max_epss)}` : ""}\n` +
        `Fix version: ${evidence.fix_version ?? "unknown"}\n` +
        `Match confidence: ${evidence.match_confidence}\n\n` +
        `${ASSESSMENT_PROMPT_RULES}`;

      const answer = await ctx.sample(prompt);
      if (!answer) {
        return ok(
          { mode: "evidence_package", evidence, schema: ASSESSMENT_SCHEMA, next: "save_assessment" },
          `${todo.program}: sampling was requested but the client did not answer, so the evidence package came back instead.`,
        );
      }

      const parsed = parseJsonObject(answer.text);
      if (!parsed) {
        return fail(`assess_todo: the client answer was not a JSON object — ${answer.text.slice(0, 160)}`);
      }

      todo.assessment = normalizeAssessment(parsed, "client_sampling");
      if (todo.status === "open") todo.status = "assessed";
      todo.updated_at = new Date().toISOString();
      store.updated_at = todo.updated_at;
      ctx.store.save(store);

      return ok(
        { mode: "sampled", todo_id: todo.id, assessment: todo.assessment, status: todo.status },
        `${todo.program}: ${axisSummary(todo.assessment)}`,
      );
    },
  },
  {
    name: "save_assessment",
    module: "todos",
    title: "Save assessment",
    description: "Write an effort assessment back to a to-do (the non-sampling path). Sets the status to assessed.",
    docs:
      "The write half of the fallback: the client assessed the evidence package and reports the four axes here. The " +
      "fields mirror ASSESSMENT_SCHEMA exactly, so a verdict saved this way is indistinguishable from a sampled one.\n" +
      "This is the only tool a normal round needs to touch the store, and it writes to the server's own JSON file — " +
      "never to the Windows system, which is why the approval gate stays simple.",
    input: z.object({
      todo_id: z.string().min(1).describe("The id from list_todos"),
      exe_swap_only: z.boolean().describe("(a) only the .exe/file has to be replaced"),
      new_setup_needed: z.boolean().describe("(b) a new setup from the vendor is needed"),
      breaking_change_expected: z.boolean().describe("(c) a breaking change is expected"),
      affected_part: z.string().optional().describe("(d) name the part program when only part of a suite is affected"),
      reason: z.string().min(1).describe("Short justification"),
      confidence: z.enum(CONFIDENCES).optional().describe("How sure the assessment is. Defaults to medium"),
      dismiss: z.boolean().optional().describe("Set the status to dismissed instead of assessed"),
    }),
    handler: async (args, ctx) => {
      const store = ctx.store.load();
      const todo = findTodo(store, String(args.todo_id));
      if (!todo) return fail(`Unknown todo_id "${String(args.todo_id)}"`);

      todo.assessment = normalizeAssessment(
        {
          exe_swap_only: args.exe_swap_only,
          new_setup_needed: args.new_setup_needed,
          breaking_change_expected: args.breaking_change_expected,
          affected_part: args.affected_part ?? null,
          reason: args.reason,
          confidence: args.confidence ?? "medium",
        },
        "client_saved",
      );
      todo.status = args.dismiss === true ? "dismissed" : "assessed";
      todo.updated_at = new Date().toISOString();
      store.updated_at = todo.updated_at;
      ctx.store.save(store);

      return ok(
        { todo_id: todo.id, status: todo.status, assessment: todo.assessment },
        `${todo.program}: ${axisSummary(todo.assessment)} (status ${todo.status})`,
      );
    },
  },
];

/**
 * Extracts the first JSON object from a model answer.
 *
 * A sampling answer often arrives wrapped in prose or a code fence, so the text is first tried as
 * a whole and then narrowed to the outermost braces before giving up.
 */
export function parseJsonObject(text: string): Record<string, unknown> | null {
  const trimmed = text.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  const attempts = [trimmed];
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) attempts.push(trimmed.slice(start, end + 1));

  for (const attempt of attempts) {
    try {
      const parsed: unknown = JSON.parse(attempt);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
    } catch {
      // Try the next narrowing.
    }
  }
  return null;
}

function axisSummary(a: { exe_swap_only: boolean; new_setup_needed: boolean; breaking_change_expected: boolean; affected_part: string | null }): string {
  const axes = [
    `a=${a.exe_swap_only ? "exe-swap" : "not-exe-swap"}`,
    `b=${a.new_setup_needed ? "new-setup" : "no-new-setup"}`,
    `c=${a.breaking_change_expected ? "breaking" : "compatible"}`,
    `d=${a.affected_part ?? "whole program"}`,
  ];
  return axes.join(", ");
}
