// Nest encryption — the CRM data layer.
//
// The clean seam between the caller and the network: it hands the caller plain
// records on read and accepts plain records on write, transparently doing the
// client-side encrypt-on-write / decrypt-on-read when the account is
// `encrypted` and unlocked. When the account is `unencrypted` it is a
// pass-through (plaintext).
//
// HARD RULE: encryption/decryption is CLIENT-SIDE only. On an encrypted write
// we strip the sensitive plaintext fields and send only the `enc` ciphertext
// blob + cleartext scheduling metadata. The server never receives the DEK or
// plaintext content.

import {
  encryptContent,
  decryptContent,
  type ContentEnvelope,
} from "./envelope";
import { CONTENT_SCHEMA, type CrmModel } from "./contentSchema";

// A stored record as it comes off the wire: cleartext metadata + an optional
// `enc` blob (present iff this doc was encrypted) + the housekeeping markers.
export interface StoredRecord {
  _id?: string;
  enc?: ContentEnvelope | null;
  encMigrated?: boolean;
  updatedAt?: string;
  [k: string]: unknown;
}

// ---------------------------------------------------------------------------
// READ: hydrate a stored record into a plain record for the caller.
// ---------------------------------------------------------------------------

// Decrypt one record's `enc` blob (if any) and merge the recovered sensitive
// fields back on top of the cleartext metadata. No `enc` blob ⇒ pass-through
// (the record is plaintext). Throws only if a present blob fails to decrypt
// (wrong/missing DEK) — callers decide how to surface that.
export async function hydrateRecord<T extends StoredRecord>(
  model: CrmModel,
  dek: Uint8Array | null,
  record: T
): Promise<T> {
  if (!record.enc) return record; // plaintext doc — nothing to do
  if (!dek) {
    // Encrypted doc but we have no key: return the record with the sensitive
    // fields left at their blanked plaintext values rather than throwing, so a
    // locked caller can still show scheduling rows ("3 follow-ups due").
    return record;
  }
  const fields = await decryptContent<Record<string, unknown>>(dek, record.enc);
  const out = { ...record } as Record<string, unknown>;
  for (const key of CONTENT_SCHEMA[model].encrypted) {
    if (key in fields) out[key] = fields[key];
  }
  return out as T;
}

// Hydrate a whole list. Decrypt failures on individual rows are tolerated (that
// row stays blanked) so one corrupt blob can't blank the entire view.
//
// `T` is intentionally loose (not constrained to StoredRecord) so callers can
// pass their domain arrays (Person[], Task[], ...) without an index signature.
// Each record is treated structurally as a StoredRecord internally.
export async function hydrateRecords<T>(
  model: CrmModel,
  dek: Uint8Array | null,
  records: T[]
): Promise<T[]> {
  return Promise.all(
    records.map(async (r) => {
      try {
        return (await hydrateRecord(
          model,
          dek,
          r as unknown as StoredRecord
        )) as unknown as T;
      } catch {
        return r;
      }
    })
  );
}

// ---------------------------------------------------------------------------
// WRITE: turn a plain create/patch payload into an encrypted wire payload.
// ---------------------------------------------------------------------------

export interface EncryptForWriteResult {
  // The payload to actually POST/PATCH: sensitive plaintext stripped, `enc`
  // added, scheduling metadata untouched.
  payload: Record<string, unknown>;
}

// Encrypt the sensitive subset of a plain payload under the DEK, returning a
// wire payload with those plaintext fields blanked + an `enc` blob set. Because
// `enc` is a single per-doc blob, any encrypted write MUST include the full
// sensitive set — callers pass the merged full record (see buildWritePayload).
export async function encryptPayload(
  model: CrmModel,
  dek: Uint8Array,
  fullSensitive: Record<string, unknown>,
  cleartext: Record<string, unknown>,
  dekVersion = 1
): Promise<Record<string, unknown>> {
  const spec = CONTENT_SCHEMA[model];

  // Bundle every sensitive field (defaulting missing ones) so the single blob
  // is always complete and self-consistent.
  const bundle: Record<string, unknown> = {};
  for (const key of spec.encrypted) {
    bundle[key] = fullSensitive[key];
  }
  const enc = await encryptContent(dek, bundle, dekVersion);

  // Start from the cleartext scheduling fields the caller wants to write.
  const payload: Record<string, unknown> = { ...cleartext };

  // Blank the plaintext columns for every encrypted field so the server stores
  // no plaintext content.
  for (const key of spec.encrypted) {
    const blank = spec.blankWith[key];
    payload[key] = blank === "[]" ? [] : blank ?? "";
  }

  payload.enc = enc;
  payload.encMigrated = true;
  return payload;
}

// Split a flat plain record into its sensitive vs cleartext halves by the model
// schema. Helper for callers that hold one merged object.
export function splitRecord(
  model: CrmModel,
  record: Record<string, unknown>
): { sensitive: Record<string, unknown>; clear: Record<string, unknown> } {
  const spec = CONTENT_SCHEMA[model];
  const encSet = new Set(spec.encrypted);
  const sensitive: Record<string, unknown> = {};
  const clear: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    if (encSet.has(k)) sensitive[k] = v;
    else clear[k] = v;
  }
  return { sensitive, clear };
}

// High-level write helper the data layer calls.
//
// `fullRecord` is the COMPLETE plain record (merge of the existing decrypted doc
// + the user's edits) — used to assemble the complete sensitive blob, since
// `enc` is one per-doc blob and a partial bundle would drop unchanged sensitive
// fields.
//
// `changes` (optional) is the user's intended field changes only. When provided
// on an encrypted write, ONLY its CLEARTEXT keys are sent alongside the blob —
// so we don't echo back populated refs / _id / timestamps from the merged
// record (which the server's patch schema would reject). When omitted,
// `fullRecord` itself supplies the cleartext.
//
//   - encrypted account + dek  → encrypt sensitive into `enc`, blank plaintext,
//                                send only the cleartext scheduling fields
//   - otherwise                → pass the plain payload through unchanged
export async function buildWritePayload(
  model: CrmModel,
  opts: { encrypted: boolean; dek: Uint8Array | null; dekVersion?: number },
  fullRecord: Record<string, unknown>,
  changes?: Record<string, unknown>
): Promise<Record<string, unknown>> {
  if (!opts.encrypted || !opts.dek) {
    // Unencrypted: send the user's payload plaintext exactly as before. Strip
    // any stray enc housekeeping fields.
    const src = changes ?? fullRecord;
    const { enc: _enc, encMigrated: _m, tagHashes: _t, ...rest } = src;
    void _enc;
    void _m;
    void _t;
    return rest;
  }
  // Encrypted: full sensitive set from fullRecord; cleartext from `changes` if
  // given (the user's edits), else from fullRecord.
  const { sensitive } = splitRecord(model, fullRecord);
  const { clear } = splitRecord(model, changes ?? fullRecord);
  // Drop fields the patch schema can't take (refs as populated objects, _id,
  // timestamps). We keep only primitive / id-string / array cleartext values.
  const safeClear: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(clear)) {
    if (k === "_id" || k === "createdAt" || k === "updatedAt") continue;
    if (v && typeof v === "object" && !Array.isArray(v)) {
      // Populated ref object -> its id string (e.g. company:{_id,name} -> id).
      const id = (v as { _id?: unknown })._id;
      if (id != null) safeClear[k] = String(id);
      // else drop non-id objects (dates arrive as ISO strings, not objects)
      continue;
    }
    safeClear[k] = v;
  }
  return encryptPayload(model, opts.dek, sensitive, safeClear, opts.dekVersion ?? 1);
}
