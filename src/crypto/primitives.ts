// Nest encryption — client-side WebCrypto primitives.
//
// THE ENCRYPTION ENGINE. Everything here runs via WebCrypto (crypto.subtle).
// These are the shared building blocks the per-method KEK derivers and the
// unlock flow use:
//
//   - base64url encode/decode (matches the server's WrappedDek string fields)
//   - random DEK generation (32 bytes / 256-bit)
//   - AES-256-GCM encrypt/decrypt (used for BOTH wrapping the DEK and for
//     encrypting CRM content fields)
//   - HKDF-SHA256 to stretch a raw IKM into a clean 256-bit KEK
//
// These run identically in the browser (the Nest web app) and in Node 20+
// (this bridge): crypto.subtle, btoa/atob, TextEncoder/TextDecoder are all
// global in both. That is how the bridge derives the SAME KEK/DEK and produces
// the SAME ciphertext as the web client.
//
// Hard rule: the server must NEVER receive the DEK, a KEK, or plaintext
// content. These functions only ever hand wrapped/ciphertext blobs to the
// network layer.

export interface AesGcmBlob {
  iv: string; // base64url 12-byte nonce
  ct: string; // base64url ciphertext (WITHOUT the tag)
  tag: string; // base64url 16-byte GCM auth tag
}

// ---------------------------------------------------------------------------
// base64url (no padding) — the on-wire format for every encrypted/binding field
// ---------------------------------------------------------------------------

export function bytesToB64u(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uToBytes(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// ---------------------------------------------------------------------------
// DEK generation — one random 256-bit key per user, generated client-side
// ---------------------------------------------------------------------------

// A fresh 32-byte (256-bit) Data Encryption Key. NEVER sent to the server in
// this form — only ever wrapped under a KEK first (see envelope.ts).
export function generateDek(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ---------------------------------------------------------------------------
// AES-256-GCM — content encryption AND DEK wrapping
// ---------------------------------------------------------------------------

async function importAesKey(
  keyBytes: Uint8Array,
  usage: KeyUsage[]
): Promise<CryptoKey> {
  if (keyBytes.length !== 32) {
    throw new Error("aes_key_must_be_256_bit");
  }
  return crypto.subtle.importKey(
    "raw",
    bufferSource(keyBytes),
    "AES-GCM",
    false,
    usage
  );
}

// Encrypt `plaintext` under a 256-bit key. Returns { iv, ct, tag } as base64url.
// `aad` (additional authenticated data) is optional and bound into the tag.
export async function aesGcmEncrypt(
  keyBytes: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<AesGcmBlob> {
  const key = await importAesKey(keyBytes, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const params: AesGcmParams = { name: "AES-GCM", iv: bufferSource(iv) };
  if (aad) params.additionalData = bufferSource(aad);
  const buf = new Uint8Array(
    await crypto.subtle.encrypt(params, key, bufferSource(plaintext))
  );
  // WebCrypto appends the 16-byte tag to the ciphertext.
  return {
    iv: bytesToB64u(iv),
    ct: bytesToB64u(buf.slice(0, buf.length - 16)),
    tag: bytesToB64u(buf.slice(buf.length - 16)),
  };
}

// Decrypt an { iv, ct, tag } blob under a 256-bit key. Throws if the tag fails
// (wrong key / tampered ciphertext) — which is exactly the integrity guarantee.
export async function aesGcmDecrypt(
  keyBytes: Uint8Array,
  blob: AesGcmBlob,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const key = await importAesKey(keyBytes, ["decrypt"]);
  const ct = b64uToBytes(blob.ct);
  const tag = b64uToBytes(blob.tag);
  const joined = new Uint8Array(ct.length + tag.length);
  joined.set(ct, 0);
  joined.set(tag, ct.length);
  const params: AesGcmParams = {
    name: "AES-GCM",
    iv: bufferSource(b64uToBytes(blob.iv)),
  };
  if (aad) params.additionalData = bufferSource(aad);
  const buf = await crypto.subtle.decrypt(params, key, bufferSource(joined));
  return new Uint8Array(buf);
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 — stretch raw IKM into a 256-bit KEK
// ---------------------------------------------------------------------------

// Fixed application salt + info so the same IKM always derives the same KEK.
// Domain-bound so input keying material captured for Nest can't be reused to
// derive a key in another app.
const HKDF_SALT = utf8("nest.scales.baby/kek/v1");

// Derive a 256-bit KEK from raw input keying material. `info` further separates
// keys derived from the same IKM for different purposes if ever needed.
export async function hkdfKek(
  ikm: Uint8Array,
  info = "nest-dek-wrap-v1"
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    bufferSource(ikm),
    "HKDF",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: bufferSource(HKDF_SALT),
      info: bufferSource(utf8(info)),
    },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

// WebCrypto's BufferSource typing (TS 5.7+) distinguishes
// Uint8Array<ArrayBuffer> from Uint8Array<ArrayBufferLike> (the latter could be
// SharedArrayBuffer-backed). Copy into a fresh, exactly-sized ArrayBuffer and
// return an ArrayBuffer (not a view), which satisfies BufferSource cleanly and
// is also a runtime no-op-safe copy.
function bufferSource(bytes: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.length);
  new Uint8Array(ab).set(bytes);
  return ab;
}
