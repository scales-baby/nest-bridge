// Bridge crypto — REUSES the EXACT same client crypto modules the Nest web app
// uses, so reads/writes round-trip byte-for-byte with the browser.
//
// We import the shared crypto from ./crypto/*. Those modules are pure WebCrypto
// (crypto.subtle) + hash-wasm Argon2id + btoa/atob/TextEncoder/TextDecoder —
// ALL global in Node 20+. Nothing here is browser-only (no IndexedDB, no DOM),
// so it runs unchanged in this Node process. This is how we GUARANTEE the
// bridge derives the same KEK/DEK and produces the same `enc` ciphertext as the
// web client.
//
// SECURITY INVARIANT: the DEK and password live ONLY in this process's memory.
// The Nest server only ever receives the wrapped-DEK fetch (it sends US the
// wrap), ciphertext on writes, and never the password/DEK/plaintext.

import { derivePasswordKek } from "./crypto/kek/password";
import { unwrapDek, type WrappedDekRecord } from "./crypto/envelope";
import {
  buildWritePayload,
  hydrateRecord,
  type StoredRecord,
} from "./crypto/crmData";
import { CONTENT_SCHEMA, type CrmModel } from "./crypto/contentSchema";

export type { CrmModel, WrappedDekRecord, StoredRecord };
export { CONTENT_SCHEMA, buildWritePayload, hydrateRecord };

// Derive the password KEK (Argon2id, matching the browser exactly) from the
// stored salt/params, then unwrap the DEK locally. Returns the raw DEK bytes —
// they never leave this process.
export async function unlockDekWithPassword(
  password: string,
  wrap: WrappedDekRecord
): Promise<{ dek: Uint8Array; dekVersion: number }> {
  if (!wrap.kdfSalt) throw new Error("password_salt_missing");
  const kek = await derivePasswordKek(password, wrap.kdfSalt, wrap.kdf);
  const dek = await unwrapDek(kek, wrap);
  return { dek, dekVersion: wrap.dekVersion ?? 1 };
}

// The encrypted-vs-clear field split, for callers that want to know which keys
// a model encrypts (e.g. to validate a write payload).
export function encryptedFieldsFor(model: CrmModel): string[] {
  return CONTENT_SCHEMA[model].encrypted;
}
