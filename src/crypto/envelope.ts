// Nest encryption — envelope wrap/unwrap + content helpers.
//
// THE ENVELOPE MODEL: one DEK per user, wrapped under a per-method KEK. This
// module is method-agnostic — it takes a raw 256-bit KEK (whatever method
// produced it) and wraps or unwraps the DEK with it. The KEK derivation itself
// lives in crypto/kek/*.
//
// It also exposes the content encrypt/decrypt helpers the DATA LAYER uses to
// encrypt CRM fields under the DEK.

import {
  aesGcmEncrypt,
  aesGcmDecrypt,
  utf8,
  fromUtf8,
  type AesGcmBlob,
} from "./primitives";

// What the client sends to /api/keys/wrap. Already-encrypted; no secret leaks.
export interface WrappedDekPayload {
  method: "wallet" | "passkey" | "password";
  binding: string | null;
  kdfSalt: string | null;
  wrappedKey: string; // base64url ciphertext (the wrapped DEK)
  iv: string;
  authTag: string;
  kdf: Record<string, unknown>;
  dekVersion: number;
  label?: string;
}

// What the client reads back from the server to reconstruct the KEK and
// unwrap the DEK.
export interface WrappedDekRecord {
  method: "wallet" | "passkey" | "password";
  binding: string | null;
  kdfSalt: string | null;
  wrappedKey: string;
  iv: string;
  authTag: string;
  kdf: Record<string, unknown>;
  dekVersion: number;
}

// ---------------------------------------------------------------------------
// DEK wrap / unwrap (the envelope)
// ---------------------------------------------------------------------------

// Wrap the DEK under a method's KEK, producing the blob to POST to the server.
export async function wrapDek(
  kek: Uint8Array,
  dek: Uint8Array,
  meta: {
    method: WrappedDekPayload["method"];
    binding: string | null;
    kdfSalt: string | null;
    kdf: Record<string, unknown>;
    dekVersion?: number;
    label?: string;
  }
): Promise<WrappedDekPayload> {
  const blob = await aesGcmEncrypt(kek, dek);
  return {
    method: meta.method,
    binding: meta.binding,
    kdfSalt: meta.kdfSalt,
    wrappedKey: blob.ct,
    iv: blob.iv,
    authTag: blob.tag,
    kdf: meta.kdf,
    dekVersion: meta.dekVersion ?? 1,
    label: meta.label,
  };
}

// Unwrap the DEK from a stored record using a freshly re-derived KEK. Throws on
// a bad KEK (GCM tag mismatch) — that's the integrity check.
export async function unwrapDek(
  kek: Uint8Array,
  record: WrappedDekRecord
): Promise<Uint8Array> {
  const blob: AesGcmBlob = {
    iv: record.iv,
    ct: record.wrappedKey,
    tag: record.authTag,
  };
  return aesGcmDecrypt(kek, blob);
}

// ---------------------------------------------------------------------------
// Content encryption helpers
// ---------------------------------------------------------------------------

// The `enc` envelope stored on each CRM doc.
export interface ContentEnvelope {
  v: number; // dekVersion used
  iv: string;
  ct: string;
  tag: string;
}

// Encrypt a CRM document's sensitive fields under the DEK. Caller passes a plain
// object of the to-be-hidden fields; we JSON-serialise + AES-GCM it into one
// `enc` blob (per-doc, not per-field, to minimise IV management).
export async function encryptContent(
  dek: Uint8Array,
  fields: Record<string, unknown>,
  dekVersion = 1
): Promise<ContentEnvelope> {
  const blob = await aesGcmEncrypt(dek, utf8(JSON.stringify(fields)));
  return { v: dekVersion, iv: blob.iv, ct: blob.ct, tag: blob.tag };
}

// Decrypt an `enc` envelope back into the original fields object.
export async function decryptContent<T = Record<string, unknown>>(
  dek: Uint8Array,
  env: ContentEnvelope
): Promise<T> {
  const bytes = await aesGcmDecrypt(dek, {
    iv: env.iv,
    ct: env.ct,
    tag: env.tag,
  });
  return JSON.parse(fromUtf8(bytes)) as T;
}
