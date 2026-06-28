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

  // 1) Fetch the password-wrapped DEK blob + the account's encryption state.
  log(`Connecting to ${apiUrl} …`);
  let wrapInfo: Awaited<ReturnType<NestClient["getBridgeWrap"]>>;
  try {
    wrapInfo = await client.getBridgeWrap();
  } catch (e) {
    log(
      "Failed to reach Nest or authenticate the API key:",
      e instanceof Error ? e.message : String(e)
    );
    process.exit(1);
  }

  const encrypted = wrapInfo.encState === "encrypted";
  let vault: Vault = { encrypted, dek: null, dekVersion: 1 };

  if (!encrypted) {
    log(
      "Account is NOT end-to-end encrypted — running in pass-through mode (no key needed)."
    );
  } else if (!wrapInfo.hasPasswordWrap || !wrapInfo.wrap) {
    log(
      "Account is encrypted but has NO password unlock method. The bridge unlocks by password; add a password method in Nest → Settings → Encryption, then retry. Continuing LOCKED (content will be blank)."
    );
  } else {
    // 2) Get the password. Priority: env/connector config (NEST_PASSWORD) for
    // non-interactive launches (Claude Desktop / OpenAI inject user_config as
    // env), else a hidden TTY prompt for manual terminal runs. When launched
    // WITHOUT a real interactive terminal AND without NEST_PASSWORD (e.g. a
    // Claude Desktop connector with the field left blank), DO NOT try to read
    // the MCP stdio pipe — continue locked with a clear message instead.
    let password = process.env.NEST_PASSWORD || "";
    if (!password) {
      const interactive = hasInteractiveTty();
      if (interactive) {
        password = await promptHidden("Nest encryption password: ");
      } else {
        log(
          "No NEST_PASSWORD set and no interactive terminal — set the password in your connector config (Claude Desktop / OpenAI) or run the bridge in a terminal to be prompted. Continuing LOCKED (content will be blank)."
        );
      }
    }
    if (!password) {
      log("No password provided — continuing LOCKED (content will be blank).");
    } else {
      // 3) Derive the password KEK (Argon2id, matches the browser) → unwrap DEK.
      log("Deriving key (Argon2id) and unwrapping the DEK locally …");
      try {
        const { dek, dekVersion } = await unlockDekWithPassword(
          password,
          wrapInfo.wrap
        );
        vault = { encrypted: true, dek, dekVersion };
        log("Unlocked. The DEK is held in memory only; the server never sees it.");
      } catch (e) {
        log(
          "Unlock FAILED (wrong password or wrap mismatch):",
          e instanceof Error ? e.message : String(e),
          "— continuing LOCKED."
        );
      }
    }
    // Best-effort scrub of the password reference.
    password = "";
  }

  // Determine write capability from the key's scopes (the server still enforces
  // authoritatively per-route). The bridge-wrap endpoint reports the key's
  // scopes; a read-only key gets a clean "read-only" message instead of a 403.
  const scopes = wrapInfo.scopes ?? [];
  let canWrite = scopes.some((s) => WRITE_SCOPES.has(s));
  if (process.env.NEST_READ_ONLY === "1") canWrite = false;
  log(
    `Key scopes: ${scopes.join(", ") || "(unknown)"} → ${canWrite ? "read+write" : "read-only"}.`
  );

  const data = new DataLayer(client, vault);
  const server = await buildServer({
    data,
    canWrite,
    encrypted,
    unlocked: vault.dek !== null,
  });

  await runStdio(server);
  log("MCP server ready (stdio). Connect Claude to this process.");
}

main().catch((e) => {
  console.error("[nest-bridge] fatal:", e);
  process.exit(1);
});
