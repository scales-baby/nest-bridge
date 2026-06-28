// E2E: fast-connect + background-unlock proof against a MOCK Nest.
//
// Proves the 1.0.2 decouple:
//   1) The MCP initialize/connect returns FAST (well under a 2-3s health-check
//      window) even though the unlock (Argon2id) takes seconds.
//   2) tools/list works immediately after connect.
//   3) A tool call (get_digest) AFTER connect waits for the background unlock,
//      then returns DECRYPTED data from the mock Nest.
//   4) A WRONG password → the tool call returns a clean "Could not unlock…"
//      error, and connect + tools/list still succeed.
//
// The mock Nest serves a REAL Argon2id password-wrapped DEK (built with the
// SHIPPED crypto) and encrypted content; it never sees the password or DEK.
// It does NOT touch prod nest.scales.baby or any real data.

import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { generateDek } from "../dist/crypto/primitives.js";
import { wrapDek } from "../dist/crypto/envelope.js";
import { derivePasswordKekNew } from "../dist/crypto/kek/password.js";
import { buildWritePayload } from "../dist/crypto/crmData.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ENTRY = path.join(__dirname, "..", "dist", "index.js");

const PASSWORD = "correct horse battery staple 42";

let pass = 0,
  fail = 0;
const ok = (name, cond) => {
  if (cond) {
    pass++;
    console.log("  PASS", name);
  } else {
    fail++;
    console.log("  FAIL", name);
  }
};

// ---- Build a real wrapped DEK + an encrypted digest the mock will serve -----
const dek = generateDek();
const kekRes = await derivePasswordKekNew(PASSWORD);
const wrapped = await wrapDek(kekRes.kek, dek, {
  method: "password",
  binding: "password",
  kdfSalt: kekRes.kdfSalt,
  kdf: kekRes.kdf,
  dekVersion: 1,
});
const wrapRecord = {
  method: "password",
  binding: "password",
  kdfSalt: wrapped.kdfSalt,
  wrappedKey: wrapped.wrappedKey,
  iv: wrapped.iv,
  authTag: wrapped.authTag,
  kdf: wrapped.kdf,
  dekVersion: wrapped.dekVersion,
};

const SECRET_NAME = "Ada Lovelace (decrypted via bridge)";
// Encrypt a person the way the web client stores it (blanked plaintext + enc).
const encPerson = await buildWritePayload(
  "person",
  { encrypted: true, dek, dekVersion: 1 },
  { name: SECRET_NAME, notes: "secret note", status: "met" },
  { name: SECRET_NAME, notes: "secret note", status: "met" }
);
const storedPerson = { _id: "p1", ...encPerson };

// ---- Mock Nest HTTP server --------------------------------------------------
const envelope = (data) => JSON.stringify({ data, error: null });

function startMockNest() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = req.url || "";
      res.setHeader("Content-Type", "application/json");
      if (url.startsWith("/api/keys/bridge-wrap")) {
        res.end(
          envelope({
            encState: "encrypted",
            scopes: ["crm:read.full", "crm:write"],
            hasPasswordWrap: true,
            wrap: wrapRecord,
          })
        );
        return;
      }
      if (url.startsWith("/api/digest")) {
        // The server returns ciphertext; the bridge decrypts locally. The
        // digest here embeds the encrypted person so we can prove decryption.
        res.end(
          envelope({ followUps: [storedPerson], openTasks: [], generatedAt: 1 })
        );
        return;
      }
      if (url.startsWith("/api/people")) {
        res.end(envelope([storedPerson]));
        return;
      }
      res.statusCode = 404;
      res.end(envelope(null));
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

async function connectBridge(env) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [ENTRY],
    env: { ...process.env, ...env },
    stderr: "ignore",
  });
  const client = new Client(
    { name: "e2e", version: "1.0.0" },
    { capabilities: {} }
  );
  const t0 = Date.now();
  await client.connect(transport);
  const connectMs = Date.now() - t0;
  return { client, transport, connectMs };
}

// ---- Run --------------------------------------------------------------------
const { server, url } = await startMockNest();

try {
  // === CASE A: correct password ===
  console.log("CASE A — correct password");
  {
    const { client, transport, connectMs } = await connectBridge({
      NEST_API_URL: url,
      NEST_API_KEY: "nest_test_key",
      NEST_PASSWORD: PASSWORD,
      NEST_NON_INTERACTIVE: "1",
    });

    console.log(`  connect handshake: ${connectMs}ms`);
    ok("connect returns FAST (<2000ms)", connectMs < 2000);

    const t0 = Date.now();
    const tools = await client.listTools();
    const listMs = Date.now() - t0;
    console.log(`  tools/list: ${listMs}ms, ${tools.tools.length} tools`);
    ok("tools/list works immediately", tools.tools.length >= 20);
    ok("tools/list is fast (<1000ms)", listMs < 1000);

    // list_people AFTER connect: must wait for the background unlock then
    // return DECRYPTED content (the bridge decrypts list reads locally).
    const res = await client.callTool({
      name: "list_people",
      arguments: {},
    });
    const text = res.content?.[0]?.text ?? "";
    ok("list_people not an error", res.isError !== true);
    ok(
      "list_people returns DECRYPTED name (background unlock awaited)",
      text.includes(SECRET_NAME)
    );

    // get_digest also works (passes through the unlock gate) after connect.
    const dres = await client.callTool({ name: "get_digest", arguments: {} });
    ok("get_digest not an error", dres.isError !== true);

    await transport.close();
  }

  // === CASE B: wrong password ===
  console.log("CASE B — wrong password");
  {
    const { client, transport, connectMs } = await connectBridge({
      NEST_API_URL: url,
      NEST_API_KEY: "nest_test_key",
      NEST_PASSWORD: "this is the WRONG password",
      NEST_NON_INTERACTIVE: "1",
    });

    console.log(`  connect handshake: ${connectMs}ms`);
    ok("connect still returns FAST (<2000ms)", connectMs < 2000);

    const tools = await client.listTools();
    ok("tools/list still works on wrong password", tools.tools.length >= 20);

    const res = await client.callTool({ name: "list_people", arguments: {} });
    const text = res.content?.[0]?.text ?? "";
    console.log("  list_people error text:", text.slice(0, 120));
    ok("wrong-password tool call is an error", res.isError === true);
    ok(
      "error message is the clean 'Could not unlock' wording",
      /could not unlock/i.test(text)
    );

    await transport.close();
  }

  // === CASE C: invalid API key (endpoint 404/401) ===
  console.log("CASE C — invalid key / endpoint failure");
  {
    const { client, transport } = await connectBridge({
      NEST_API_URL: "http://127.0.0.1:1", // unreachable
      NEST_API_KEY: "nest_bad",
      NEST_PASSWORD: PASSWORD,
      NEST_NON_INTERACTIVE: "1",
    });
    const tools = await client.listTools();
    ok("tools/list works despite unreachable Nest", tools.tools.length >= 20);
    const res = await client.callTool({ name: "list_people", arguments: {} });
    ok("unreachable Nest → tool call is a clean error", res.isError === true);
    const text = res.content?.[0]?.text ?? "";
    ok("error mentions could-not-unlock", /could not unlock/i.test(text));
    await transport.close();
  }
} finally {
  server.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
