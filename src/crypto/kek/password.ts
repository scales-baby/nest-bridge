// Nest encryption — password-derived KEK.
//
// The KEK is derived CLIENT-SIDE with Argon2id via hash-wasm (a portable WASM
// build), so the password and the KEK never reach the server.
//
//   KEK = Argon2id(password, salt)   (32-byte output)
//
// We store ONLY the random salt + the Argon2 params (m/t/p) in the wrap record
// so the same password re-derives the same KEK on any device. The password and
// KEK are never persisted or transmitted.

import { argon2id } from "hash-wasm";
import { bytesToB64u, b64uToBytes } from "../primitives";

// Argon2id params (m=64MB, t=3, p=1). Tunable later via the stored kdf
// descriptor without breaking old wraps (each row carries its own params).
export const ARGON2_PARAMS = {
  // hash-wasm takes memory in KiB; 64 MiB = 65536 KiB.
  memorySizeKiB: 65536,
  iterations: 3,
  parallelism: 1,
  hashLength: 32,
} as const;

export interface PasswordKekResult {
  kek: Uint8Array;
  kdfSalt: string; // base64url salt to persist
  kdf: Record<string, unknown>;
}

// Derive a NEW password KEK (registration / set-password). Generates a fresh
// random 16-byte salt and returns the KEK + the descriptor to persist.
export async function derivePasswordKekNew(
  password: string
): Promise<PasswordKekResult> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const kek = await runArgon2(password, salt);
  return {
    kek,
    kdfSalt: bytesToB64u(salt),
    kdf: {
      alg: "argon2id",
      m: ARGON2_PARAMS.memorySizeKiB,
      t: ARGON2_PARAMS.iterations,
      p: ARGON2_PARAMS.parallelism,
    },
  };
}

// Re-derive an EXISTING password KEK at unlock time, using the stored salt
// (and, if present, the stored params).
export async function derivePasswordKek(
  password: string,
  kdfSalt: string,
  kdf?: Record<string, unknown>
): Promise<Uint8Array> {
  const salt = b64uToBytes(kdfSalt);
  return runArgon2(password, salt, kdf);
}

async function runArgon2(
  password: string,
  salt: Uint8Array,
  kdf?: Record<string, unknown>
): Promise<Uint8Array> {
  const memorySize =
    typeof kdf?.m === "number" ? (kdf.m as number) : ARGON2_PARAMS.memorySizeKiB;
  const iterations =
    typeof kdf?.t === "number" ? (kdf.t as number) : ARGON2_PARAMS.iterations;
  const parallelism =
    typeof kdf?.p === "number" ? (kdf.p as number) : ARGON2_PARAMS.parallelism;

  const hex = await argon2id({
    password,
    salt,
    memorySize,
    iterations,
    parallelism,
    hashLength: ARGON2_PARAMS.hashLength,
    outputType: "hex",
  });
  // hex -> bytes
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// Binding + KDF descriptor to persist with a password-wrapped DEK. The binding
// is the "password" sentinel (one password wrap per user).
export function passwordWrapMeta(result: PasswordKekResult) {
  return {
    method: "password" as const,
    binding: "password",
    kdfSalt: result.kdfSalt,
    kdf: result.kdf,
  };
}
