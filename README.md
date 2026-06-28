# nest-bridge

A local [MCP](https://modelcontextprotocol.io) bridge so your AI can read and write your end-to-end-encrypted [Nest](https://nest.scales.baby) data (people, companies, tasks, events) while Nest's servers only ever see ciphertext.

The bridge runs **on your machine**. It unlocks your encryption key locally from your password, holds it in memory, and decrypts on read / encrypts on write right there. **Nest never receives your password, your key, or your plaintext** - only the already-encrypted blobs and your API key.

```
your AI  <--stdio MCP-->  nest-bridge (your machine)  <--HTTPS-->  nest.scales.baby
                          |  decrypts on read         |
                          |  encrypts on write        |  stores ciphertext only
                          |  holds the key in memory  |
```

## Security model

- Your **API key** and your **encryption password** stay on your machine. You supply them at runtime as environment variables (or, for the Claude Desktop connector, into your OS keychain).
- The bridge fetches only your **password-wrapped key** (ciphertext plus the public salt) from Nest, derives your key locally with Argon2id, unwraps the key **locally**, and keeps it in memory.
- **Reads** decrypt locally. **Writes** encrypt locally. The server stores only the encrypted blob with the plaintext columns blanked. Nest never receives the key, the password, or your plaintext.
- The crypto is the **same WebCrypto + Argon2id (hash-wasm) code the Nest web app uses**, so reads and writes round-trip byte-for-byte with the browser. See `src/crypto/`.
- **Your AI provider sees what it reads.** "Nest can't read your data" is not the same as "no one but you" once you connect an AI: the model you connect (Claude, OpenAI, etc.) sees the decrypted content the bridge returns to it. That is the point of connecting an AI. Mint a **read-only** key if you do not want it to write.
- A **read-only** key cannot write; a **full-control** key can. The server enforces this independently of the bridge.

This repository contains only the bridge and the client-side crypto. There is no server code, no database, and no secrets here.

## Mint a key in Nest

Open **Nest then Settings then Connect your AI** and create a key.

- **Read-only** (the default) lets your AI read your data.
- **Full control** also lets it create and update records.

Copy the key when it is shown (it appears once). It looks like `nest_ab12cd34_...`.

## Run it (npx)

```bash
NEST_API_KEY="nest_ab12cd34_..." \
NEST_PASSWORD="your-encryption-password" \
NEST_NON_INTERACTIVE=1 \
npx -y @scales-baby/nest-bridge
```

The bridge fetches your wrapped key, unwraps it locally, and starts an MCP server on stdio. Point any MCP client at the same command. (`-y` skips npm's install-confirm prompt so the launch can't hang.)

When you run the bridge **manually** in a real interactive terminal, you can omit `NEST_PASSWORD` and `NEST_NON_INTERACTIVE`; the bridge then prompts `Nest encryption password:` with hidden input. This hidden prompt only works in a terminal. An **MCP-spawned** server has no TTY, so when an AI launches the bridge the password must come from config or your OS keychain (see below), not a prompt.

### Configuration (environment variables)

| Var                    | Default                    | Notes                                              |
| ---------------------- | -------------------------- | -------------------------------------------------- |
| `NEST_API_KEY`         | (required)                 | Your scoped key from Nest.                          |
| `NEST_PASSWORD`        | (prompt)                   | Set it to run non-interactively; else prompted.     |
| `NEST_API_URL`         | `https://nest.scales.baby` | Override only to test against another instance.     |
| `NEST_NON_INTERACTIVE` | (unset)                    | Set to `1` when launched by an app (no prompt).     |
| `NEST_READ_ONLY`       | (unset)                    | Set to `1` to force read-only locally.              |

If your account is not end-to-end encrypted, the bridge runs in pass-through mode and no password is needed.

## Claude Desktop (one-click `.mcpb`)

Build the connector bundle, then double-click it (or drag it onto Claude Desktop):

```bash
npm install
npm run pack:mcpb     # produces dist/scales-nest.mcpb
```

Claude Desktop opens an install panel for "Nest by SCALES" and asks for your **Nest API key** and **Nest encryption password**. Both are marked sensitive, so Claude Desktop stores them in your OS keychain (macOS Keychain / Windows Credential Manager), not in a plain file. Leave **Nest URL** at its default and enable it.

**Where your password lives (pick one):**

- **Claude Desktop `.mcpb` (recommended):** stores your password in the OS keychain.
- **`claude mcp add` (below):** stores it in your local Claude config (`~/.claude.json`), and the command line lands in your shell history. That is local-only, but prefer the `.mcpb` if you want it in the keychain.

## Per-AI config snippets

**Claude Code (CLI):**

```bash
claude mcp add nest \
  --env NEST_API_KEY=nest_ab12cd34_... \
  --env NEST_PASSWORD=your-encryption-password \
  --env NEST_NON_INTERACTIVE=1 \
  -- npx -y @scales-baby/nest-bridge
```

After adding, reload so the tools appear: run `claude --continue` to resume the current session and load the MCP.

**OpenAI / any stdio MCP client (JSON):**

```json
{
  "command": "npx",
  "args": ["-y", "@scales-baby/nest-bridge"],
  "env": {
    "NEST_API_KEY": "nest_ab12cd34_...",
    "NEST_PASSWORD": "your-encryption-password",
    "NEST_NON_INTERACTIVE": "1"
  }
}
```

Note: OpenAI's **remote / hosted** MCP is metadata-only on encrypted accounts. Only the **local** bridge returns decrypted content, because decryption happens on your machine.

## Tools

People, Companies, Tasks, Events, each with `list_*`, `get_*`, `search_*`, `create_*`, `update_*`, plus `complete_task` and `get_digest`. 22 tools in all. Notes ride on the person / company / task / event they belong to.

- **Reads** fetch ciphertext from Nest, decrypt locally, return plaintext to your AI.
- **Writes** take your AI's plaintext, encrypt locally, send ciphertext to Nest.

If you minted a read-only key, the write tools politely decline (and Nest enforces it on the server too).

## Build from source

```bash
git clone https://github.com/scales-baby/nest-bridge.git
cd nest-bridge
npm install
npm run build        # tsc → dist/
npm test             # crypto round-trip proof
npm start            # run the built bridge (needs the env above)
```

## License

MIT. See [LICENSE](./LICENSE).
