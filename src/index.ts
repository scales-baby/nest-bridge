#!/usr/bin/env node
// Nest local MCP bridge — entry point.
//
// Runs on the USER's machine. Holds the user's DEK in memory after deriving it
// from their PASSWORD; the Nest SERVER never receives the DEK, the password, or
// plaintext. Reads decrypt locally, writes encrypt locally.
//
// Config (env or .env in cwd):
//   NEST_API_URL   default https://nest.scales.baby
//   NEST_API_KEY   the user's scoped key (nest_<prefix>_<secret>)  [required]
//   NEST_PASSWORD  OPTIONAL — if unset, prompt securely at startup (preferred)
//
// All logging goes to stderr so it never corrupts the stdio MCP protocol.

import { openSync, closeSync } from "node:fs";

import { NestClient } from "./nestClient";
import { unlockDekWithPassword } from "./crypto";
import { DataLayer, type Vault } from "./data";
import { buildServer, runStdio } from "./mcp";
import { promptHidden } from "./prompt";

const log = (...a: unknown[]) => console.error("[nest-bridge]", ...a);

const WRITE_SCOPES = new Set(["crm:write", "tasks:write"]);

// True only when launched from a real interactive terminal where a hidden
// password prompt is safe. Claude Desktop / OpenAI launch us non-interactively
// (stdio wired to the MCP client), so this is false there and we never touch
// the protocol pipe trying to read a password.
function hasInteractiveTty(): boolean {
  if (process.env.NEST_NON_INTERACTIVE === "1") return false;
  try {
    // openSync throws if there is no controlling terminal.
    const fd = openSync("/dev/tty", "r");
    closeSync(fd);
    return true;
  } catch {
    return process.stdin.isTTY === true && process.stdout.isTTY === true;
  }
}

async function main() {
  const apiUrl = process.env.NEST_API_URL || "https://nest.scales.baby";
  const apiKey = process.env.NEST_API_KEY || "";
  if (!apiKey) {
    log(
      "Missing NEST_API_KEY. Mint a scoped key in Nest → Settings → Connect your AI, then set NEST_API_KEY."
    );
    process.exit(1);
  }

  const client = new NestClient({ apiUrl, apiKey });

  // The vault is mutated IN PLACE once the background unlock resolves; the
  // DataLayer holds this same reference, so a tool call that awaits the unlock
  // gate sees the populated DEK. canWrite/encrypted are likewise filled in by
  // the background unlock and read lazily by the write gate.
  const vault: Vault = { encrypted: false, dek: null, dekVersion: 1 };
  let canWrite = false;
  let encrypted = false;
  let unlocked = false;

  // ---- BACKGROUND UNLOCK ----------------------------------------------------
  // We do NOT block the MCP handshake on this. It runs right after we connect
  // the stdio transport (kicked off below). Tool calls await `unlockGate`; a
  // rejection carries a clean, human-readable reason that surfaces to Claude.
  let unlockPromise: Promise<void> | null = null;

  async function doUnlock(): Promise<void> {
    // 1) Fetch the password-wrapped DEK blob + the account's encryption state.
    log(`Connecting to ${apiUrl} …`);
    let wrapInfo: Awaited<ReturnType<NestClient["getBridgeWrap"]>>;
    try {
      wrapInfo = await client.getBridgeWrap();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("Failed to reach Nest or authenticate the API key:", msg);
      throw new Error(
        `Could not unlock: failed to reach Nest or the API key is invalid (${msg}).`
      );
    }

    encrypted = wrapInfo.encState === "encrypted";
    vault.encrypted = encrypted;

    // Determine write capability from the key's scopes (the server still
    // enforces authoritatively per-route).
    const scopes = wrapInfo.scopes ?? [];
    canWrite = scopes.some((s) => WRITE_SCOPES.has(s));
    if (process.env.NEST_READ_ONLY === "1") canWrite = false;
    log(
      `Key scopes: ${scopes.join(", ") || "(unknown)"} → ${canWrite ? "read+write" : "read-only"}.`
    );

    if (!encrypted) {
      log(
        "Account is NOT end-to-end encrypted — running in pass-through mode (no key needed)."
      );
      unlocked = true;
      return;
    }

    if (!wrapInfo.hasPasswordWrap || !wrapInfo.wrap) {
      log(
        "Account is encrypted but has NO password unlock method. The bridge unlocks by password; add a password method in Nest → Settings → Encryption, then retry. Continuing LOCKED (content will be blank)."
      );
      throw new Error(
        "Could not unlock: this encrypted account has no password unlock method. Add a password method in Nest → Settings → Encryption."
      );
    }

    // 2) Get the password. Priority: env/connector config (NEST_PASSWORD) for
    // non-interactive launches (Claude Desktop / OpenAI inject user_config as
    // env), else a hidden TTY prompt for manual terminal runs. When launched
    // WITHOUT a real interactive terminal AND without NEST_PASSWORD, do NOT try
    // to read the MCP stdio pipe — fail the unlock with a clear message.
    let password = process.env.NEST_PASSWORD || "";
    if (!password) {
      if (hasInteractiveTty()) {
        password = await promptHidden("Nest encryption password: ");
      } else {
        log(
          "No NEST_PASSWORD set and no interactive terminal — set the password in your connector config (Claude Desktop / OpenAI) or run the bridge in a terminal to be prompted. Continuing LOCKED (content will be blank)."
        );
      }
    }
    if (!password) {
      throw new Error(
        "Could not unlock: no password provided. Set NEST_PASSWORD in your connector config, or run the bridge in a terminal to be prompted."
      );
    }

    // 3) Derive the password KEK (Argon2id, matches the browser) → unwrap DEK.
    log("Deriving key (Argon2id) and unwrapping the DEK locally …");
    try {
      const { dek, dekVersion } = await unlockDekWithPassword(
        password,
        wrapInfo.wrap
      );
      vault.dek = dek;
      vault.dekVersion = dekVersion;
      unlocked = true;
      log("Unlocked. The DEK is held in memory only; the server never sees it.");
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      log("Unlock FAILED (wrong password or wrap mismatch):", msg);
      throw new Error(
        "Could not unlock: wrong password (the wrapped key failed to decrypt)."
      );
    } finally {
      // Best-effort scrub of the password reference.
      password = "";
    }
  }

  // Idempotent gate: start the unlock once, await the same promise everywhere.
  // A rejection is cached so every subsequent tool call sees the same clean
  // error (we don't retry a wrong password on each call).
  function ensureUnlocked(): Promise<void> {
    if (!unlockPromise) unlockPromise = doUnlock();
    return unlockPromise;
  }

  const data = new DataLayer(client, vault, ensureUnlocked);
  const server = await buildServer({
    data,
    ensureUnlocked,
    getStatus: () => ({ canWrite, encrypted, unlocked }),
  });

  // ---- CONNECT FIRST (instant handshake) ------------------------------------
  // Connect the stdio transport BEFORE unlocking so the client's MCP
  // initialize/connect probe completes immediately (no Argon2id/fetch on the
  // handshake path). tools/list works right away.
  await runStdio(server);
  log("MCP server ready (stdio). Connect Claude to this process.");

  // ---- THEN unlock in the background ----------------------------------------
  // Kick it off now so the DEK is usually ready by the first tool call; if a
  // tool is called sooner, DataLayer.ensureUnlocked() awaits this same promise.
  // Swallow the rejection here (it's surfaced per tool call); never crash the
  // process — tools/list must keep working even if unlock fails.
  ensureUnlocked().catch(() => {});
}

main().catch((e) => {
  console.error("[nest-bridge] fatal:", e);
  process.exit(1);
});
