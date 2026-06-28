// Bridge — secure hidden password prompt (stdin, no echo).
//
// Prompts on the CONTROLLING TTY so it works even when stdio is wired to an MCP
// client over the pipe. We write the prompt to stderr and read the password
// from the TTY with echo OFF, then restore terminal state. The password is held
// only in memory by the caller and never persisted.

import { createInterface } from "node:readline";
import { openSync, createReadStream } from "node:fs";

// Read a line from the TTY with input hidden. Falls back to stdin if no TTY.
export async function promptHidden(question: string): Promise<string> {
  // Prefer the real terminal so we don't consume the MCP stdio pipe.
  let input: NodeJS.ReadableStream;
  let isTty = false;
  try {
    const fd = openSync("/dev/tty", "r");
    input = createReadStream("", { fd });
    isTty = true;
  } catch {
    input = process.stdin;
    isTty = process.stdin.isTTY === true;
  }

  const output = process.stderr;

  return new Promise<string>((resolve, reject) => {
    const rl = createInterface({ input, output, terminal: true });

    // Mute echo: override the readline output writer so typed chars don't show.
    let muted = false;
    const realWrite = (
      output as unknown as { write: (s: string) => boolean }
    ).write.bind(output);
    // @ts-expect-error patching the stream write for masking
    rl._writeToOutput = (s: string) => {
      if (muted) {
        // Allow the prompt line + newline through; mask everything else.
        if (s.includes(question)) realWrite(s);
        else if (s === "\n" || s === "\r\n") realWrite(s);
        return;
      }
      realWrite(s);
    };

    rl.question(question, (answer) => {
      muted = false;
      rl.close();
      // Newline after the (hidden) input so the next output starts cleanly.
      output.write("\n");
      resolve(answer);
    });
    muted = true;

    rl.on("SIGINT", () => {
      rl.close();
      reject(new Error("cancelled"));
    });

    void isTty;
  });
}
