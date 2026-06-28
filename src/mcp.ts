// Bridge — the MCP server (stdio transport).
//
// Exposes list/get/search/create/update tools for people, companies, tasks,
// events (+ get_digest). Reads decrypt locally; writes encrypt locally. The
// Nest server only ever sees ciphertext + the API key.
//
// Scopes: the bridge respects the key's scopes by simply forwarding requests —
// the Nest REST API enforces scope per-route (a read-only key gets 403 on a
// write, surfaced back to Claude as an error). We also pre-gate write tools
// when the key is known to be read-only, for a cleaner message.

import { z } from "zod";

import { DataLayer } from "./data";
import { NestApiError } from "./nestClient";
import type { CrmModel } from "./crypto";

// The MCP SDK is ESM-only; this file compiles to CommonJS, so we load the SDK
// via dynamic import() at runtime (a CJS require() of an ESM-only package
// throws). McpServer is typed loosely to keep the surface simple.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type McpServer = any;

async function loadSdk(): Promise<{
  McpServer: new (info: { name: string; version: string }) => McpServer;
  StdioServerTransport: new () => unknown;
}> {
  const mcp = await import("@modelcontextprotocol/sdk/server/mcp.js");
  const stdio = await import("@modelcontextprotocol/sdk/server/stdio.js");
  return {
    McpServer: mcp.McpServer,
    StdioServerTransport: stdio.StdioServerTransport,
  };
}

// The server's view of unlock status. Because the unlock now runs in the
// BACKGROUND (so the MCP handshake returns instantly), none of these fields are
// known at buildServer() time — they are read LAZILY at tool-call time via
// getStatus(), after the in-flight unlock has settled.
export interface BridgeStatus {
  canWrite: boolean; // the key has crm:write / tasks:write
  encrypted: boolean;
  unlocked: boolean; // a DEK is held (encrypted accounts only)
}

export interface BridgeContext {
  data: DataLayer;
  // Block until the background unlock finishes; throws a clean Error if it
  // failed (wrong password / invalid key / endpoint error). Write tools call
  // this (via DataLayer) before checking canWrite, so scopes are known.
  ensureUnlocked: () => Promise<void>;
  // Current unlock status, read lazily (post-unlock) for the write gate.
  getStatus: () => BridgeStatus;
}

function jsonResult(value: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(value, null, 2) },
    ],
  };
}

function errResult(e: unknown) {
  const msg =
    e instanceof NestApiError
      ? `Nest API error (${e.status}): ${e.message}`
      : e instanceof Error
        ? e.message
        : String(e);
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: msg }],
  };
}

// Simple client-side fuzzy filter for search tools (the REST API has no text
// search on encrypted content — we decrypt locally then match).
function matches(row: Record<string, unknown>, q: string, keys: string[]): boolean {
  const needle = q.toLowerCase();
  return keys.some((k) => {
    const v = row[k];
    return typeof v === "string" && v.toLowerCase().includes(needle);
  });
}

export async function buildServer(ctx: BridgeContext): Promise<McpServer> {
  const { McpServer } = await loadSdk();
  const server: McpServer = new McpServer({
    name: "nest-bridge",
    version: "1.0.2",
  });

  // Descriptions are registered ONCE at startup, before the background unlock
  // finishes — so this note can't depend on the (not-yet-known) unlock state.
  // Tool calls themselves await the unlock; if it's an encrypted account the
  // bridge decrypts locally once unlocked. Keep the note generic + honest.
  const encNote =
    " If your Nest account is end-to-end encrypted, the bridge unlocks with your" +
    " password in the background and decrypts/encrypts locally so you see and" +
    " write real content; the server only ever sees ciphertext.";

  // Shared write-gate: tool calls go through DataLayer (which awaits the unlock)
  // for the heavy lifting, but the canWrite scope is only known post-unlock, so
  // write tools ensure the unlock settled, then check the scope for a clean
  // "read-only" message before attempting the write.
  async function ensureWritable(): Promise<void> {
    await ctx.ensureUnlocked();
    if (!ctx.getStatus().canWrite) {
      throw new Error("This API key is read-only (no write scope).");
    }
  }

  // ---- generic registrars -------------------------------------------------

  const listFilter = {
    status: z.string().optional().describe("Filter by status"),
    dueWithin: z
      .enum(["today", "week", "overdue"])
      .optional()
      .describe("Filter by next-action / due date window"),
    limit: z.number().int().min(1).max(1000).optional(),
  };

  function registerList(
    name: string,
    model: CrmModel,
    desc: string,
    extra: Record<string, z.ZodTypeAny> = {}
  ) {
    server.registerTool(
      name,
      {
        description: desc + encNote,
        inputSchema: { ...listFilter, ...extra },
      },
      async (args: Record<string, unknown>) => {
        try {
          const rows = await ctx.data.list(model, args as never);
          return jsonResult({ count: rows.length, items: rows });
        } catch (e) {
          return errResult(e);
        }
      }
    );
  }

  function registerGet(name: string, model: CrmModel, desc: string) {
    server.registerTool(
      name,
      {
        description: desc + encNote,
        inputSchema: { id: z.string().describe("The record's _id") },
      },
      async (args: { id: string }) => {
        try {
          const row = await ctx.data.get(model, args.id);
          if (!row) return errResult(new Error("not_found"));
          return jsonResult(row);
        } catch (e) {
          return errResult(e);
        }
      }
    );
  }

  function registerSearch(
    name: string,
    model: CrmModel,
    keys: string[],
    desc: string
  ) {
    server.registerTool(
      name,
      {
        description: desc + encNote,
        inputSchema: {
          query: z.string().describe("Text to fuzzy-match against content"),
          limit: z.number().int().min(1).max(1000).optional(),
        },
      },
      async (args: { query: string; limit?: number }) => {
        try {
          const rows = await ctx.data.list(model, { limit: 1000 });
          const hits = rows
            .filter((r) => matches(r, args.query, keys))
            .slice(0, args.limit ?? 50);
          return jsonResult({ count: hits.length, items: hits });
        } catch (e) {
          return errResult(e);
        }
      }
    );
  }

  function registerCreate(
    name: string,
    model: CrmModel,
    shape: Record<string, z.ZodTypeAny>,
    desc: string
  ) {
    server.registerTool(
      name,
      { description: desc + encNote, inputSchema: shape },
      async (args: Record<string, unknown>) => {
        try {
          await ensureWritable();
          const clean = Object.fromEntries(
            Object.entries(args).filter(([, v]) => v !== undefined)
          );
          const created = await ctx.data.create(model, clean);
          return jsonResult(created);
        } catch (e) {
          return errResult(e);
        }
      }
    );
  }

  function registerUpdate(
    name: string,
    model: CrmModel,
    shape: Record<string, z.ZodTypeAny>,
    desc: string
  ) {
    server.registerTool(
      name,
      {
        description: desc + encNote,
        inputSchema: { id: z.string().describe("The record's _id"), ...shape },
      },
      async (args: Record<string, unknown>) => {
        try {
          await ensureWritable();
          const { id, ...rest } = args as { id: string } & Record<string, unknown>;
          const changes = Object.fromEntries(
            Object.entries(rest).filter(([, v]) => v !== undefined)
          );
          const updated = await ctx.data.update(model, id, changes);
          return jsonResult(updated);
        } catch (e) {
          return errResult(e);
        }
      }
    );
  }

  // ---- PEOPLE -------------------------------------------------------------
  registerList(
    "list_people",
    "person",
    "List people in your CRM. Filter by status or dueWithin."
  );
  registerGet("get_person", "person", "Get one person by id, with notes.");
  registerSearch(
    "search_people",
    "person",
    ["name", "companyName", "role", "notes", "channelMet"],
    "Search people by name/company/role/notes."
  );
  registerCreate(
    "create_person",
    "person",
    {
      name: z.string().describe("Full name"),
      companyName: z.string().optional(),
      role: z.string().optional(),
      channelMet: z.string().optional(),
      status: z.string().optional().describe("cold|contacted|replied|met|in_conversation|close|customer|dead|parked"),
      nextAction: z.string().optional(),
      nextActionDate: z.string().optional().describe("ISO date"),
      linkedin: z.string().optional(),
      twitter: z.string().optional(),
      telegram: z.string().optional(),
      notes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Create a person."
  );
  registerUpdate(
    "update_person",
    "person",
    {
      name: z.string().optional(),
      companyName: z.string().optional(),
      role: z.string().optional(),
      channelMet: z.string().optional(),
      status: z.string().optional(),
      nextAction: z.string().optional(),
      nextActionDate: z.string().optional(),
      linkedin: z.string().optional(),
      twitter: z.string().optional(),
      telegram: z.string().optional(),
      notes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Update a person (only the fields you pass change)."
  );

  // ---- COMPANIES ----------------------------------------------------------
  registerList("list_companies", "company", "List companies.");
  registerGet("get_company", "company", "Get one company by id, with notes.");
  registerSearch(
    "search_companies",
    "company",
    ["name", "notes"],
    "Search companies by name/notes."
  );
  registerCreate(
    "create_company",
    "company",
    {
      name: z.string().describe("Company name"),
      city: z.string().optional(),
      category: z.string().optional(),
      website: z.string().optional(),
      notes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Create a company."
  );
  registerUpdate(
    "update_company",
    "company",
    {
      name: z.string().optional(),
      city: z.string().optional(),
      category: z.string().optional(),
      website: z.string().optional(),
      notes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Update a company."
  );

  // ---- TASKS --------------------------------------------------------------
  registerList("list_tasks", "task", "List tasks. Filter by status or dueWithin.");
  registerGet("get_task", "task", "Get one task by id, with notes.");
  registerSearch(
    "search_tasks",
    "task",
    ["title", "notes"],
    "Search tasks by title/notes."
  );
  registerCreate(
    "create_task",
    "task",
    {
      title: z.string().describe("Task title"),
      dueDate: z.string().optional().describe("ISO date"),
      status: z.string().optional().describe("open|done"),
      priority: z.string().optional().describe("high|medium|low"),
      relatedPerson: z.string().optional().describe("Person _id"),
      relatedEvent: z.string().optional().describe("Event _id"),
      notes: z.string().optional(),
    },
    "Create a task."
  );
  registerUpdate(
    "update_task",
    "task",
    {
      title: z.string().optional(),
      dueDate: z.string().optional(),
      status: z.string().optional(),
      priority: z.string().optional(),
      relatedPerson: z.string().optional(),
      relatedEvent: z.string().optional(),
      notes: z.string().optional(),
    },
    "Update a task."
  );
  server.registerTool(
    "complete_task",
    {
      description: "Mark a task done (metadata-only).",
      inputSchema: { id: z.string().describe("The task _id") },
    },
    async (args: { id: string }) => {
      try {
        await ensureWritable();
        return jsonResult(await ctx.data.completeTask(args.id));
      } catch (e) {
        return errResult(e);
      }
    }
  );

  // ---- EVENTS -------------------------------------------------------------
  registerList("list_events", "event", "List events. Filter by status.");
  registerGet("get_event", "event", "Get one event by id, with notes.");
  registerSearch(
    "search_events",
    "event",
    ["title", "notes", "researchNotes"],
    "Search events by title/notes."
  );
  registerCreate(
    "create_event",
    "event",
    {
      title: z.string().describe("Event title (kept as cleartext metadata)"),
      date: z.string().describe("ISO date"),
      city: z.string().optional(),
      venue: z.string().optional(),
      type: z.string().optional(),
      status: z.string().optional(),
      url: z.string().optional(),
      notes: z.string().optional(),
      researchNotes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Create an event."
  );
  registerUpdate(
    "update_event",
    "event",
    {
      title: z.string().optional(),
      date: z.string().optional(),
      city: z.string().optional(),
      venue: z.string().optional(),
      type: z.string().optional(),
      status: z.string().optional(),
      url: z.string().optional(),
      notes: z.string().optional(),
      researchNotes: z.string().optional(),
      tags: z.array(z.string()).optional(),
    },
    "Update an event."
  );

  // ---- DIGEST -------------------------------------------------------------
  server.registerTool(
    "get_digest",
    {
      description:
        "Get the actionable digest (overdue/today/this-week follow-ups + open tasks)." +
        encNote,
      inputSchema: {},
    },
    async () => {
      try {
        return jsonResult(await ctx.data.digest());
      } catch (e) {
        return errResult(e);
      }
    }
  );

  return server;
}

export async function runStdio(server: McpServer): Promise<void> {
  const { StdioServerTransport } = await loadSdk();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
