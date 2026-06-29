// Nest encryption — the canonical encrypted-vs-cleartext field split per CRM
// model. SINGLE SOURCE OF TRUTH for which fields get bundled into the `enc`
// blob on write and hydrated back on read.
//
// HYBRID RULE: "content" fields (names, free text, handles, "what was said")
// live ONLY inside the per-doc `enc` blob when the account is `encrypted`. The
// "scheduling / structured metadata" fields stay CLEARTEXT top-level so the
// server cron, digests, filters, sort, and pagination keep working without ever
// holding a key.
//
// This module is environment-agnostic (no WebCrypto, no DOM).

export type CrmModel = "person" | "task" | "company" | "merchant" | "event" | "route";

export interface ModelFieldSplit {
  // Sensitive fields bundled into the `enc` blob and blanked in plaintext when
  // encrypted. Order is irrelevant; these are the keys we JSON-encrypt.
  encrypted: string[];
  // Of the encrypted fields, the subset fuzzy-searched over after decrypt
  // (names/notes/free text). A subset of `encrypted`.
  searchKeys: string[];
  // Cleartext scheduling / structured metadata kept server-readable + indexed.
  // Documented here for clarity; the server keeps anything not in `encrypted`.
  clear: string[];
  // Default plaintext value to write back when a field is moved into `enc`
  // (blanking the old column). String fields -> "", arrays -> [].
  blankWith: Record<string, "" | null | "[]">;
}

// PERSON ----------------------------------------------------------------------
// Encrypted: identity + relationship content (name/company label/role/how-met/
// notes/social handles/next-action free text/tags plaintext copy).
// Clear: scheduling + status + counts + refs (so digest/cron/filters work).
const person: ModelFieldSplit = {
  encrypted: [
    "name",
    "companyName",
    "role",
    "channelMet",
    "notes",
    "linkedin",
    "twitter",
    "telegram",
    "nextAction",
    "tags",
  ],
  searchKeys: ["name", "companyName", "role", "notes", "channelMet"],
  clear: [
    "userId",
    "company", // ObjectId ref (not a name)
    "status",
    "lastContact",
    "nextActionDate",
    "reminderFiredAt",
    "source",
    "tagHashes",
    "createdAt",
    "updatedAt",
  ],
  blankWith: {
    name: "",
    companyName: "",
    role: "",
    channelMet: "",
    notes: "",
    linkedin: "",
    twitter: "",
    telegram: "",
    nextAction: "",
    tags: "[]",
  },
};

// TASK ------------------------------------------------------------------------
// Encrypted: title + body/notes (free text). Clear: due/status/priority/refs.
const task: ModelFieldSplit = {
  encrypted: ["title", "notes"],
  searchKeys: ["title", "notes"],
  clear: [
    "userId",
    "dueDate",
    "status",
    "priority",
    "relatedPerson",
    "relatedEvent",
    "reminderFiredAt",
    "createdAt",
    "updatedAt",
  ],
  blankWith: { title: "", notes: "" },
};

// COMPANY / MERCHANT / EVENT / ROUTE -----------------------------------------
// These carry mostly structured scheduling/operational metadata; the genuinely
// free-text "notes" (and a couple of note-like fields) are the sensitive
// content. We encrypt those and keep everything else cleartext so the event
// calendar and route planning stay server-side.
// COMPANY: encrypt the identifying label (name/city/category) alongside the
// free-text notes. Only contactStatus + scheduling-ish metadata + tagHashes
// stay cleartext so the server can count/filter without holding a key. City
// grouping + name search are done CLIENT-SIDE on the decrypted records.
const company: ModelFieldSplit = {
  encrypted: ["notes", "payrollFriction", "name", "city", "category"],
  searchKeys: ["notes", "payrollFriction", "name", "city"],
  clear: ["contactStatus", "tags", "tagHashes"],
  blankWith: { notes: "", payrollFriction: "", name: "", city: "", category: "" },
};

// MERCHANT: encrypt the identifying/operational content (name/city/zone/
// address/type/paymentRails) alongside notes + contact/owner free text. Only
// status enums (visitStatus/qrDeliveryStatus) + tagHashes stay cleartext so the
// QR follow-up cron + counts keep working. City/zone grouping + name search are
// CLIENT-SIDE on decrypted records.
const merchant: ModelFieldSplit = {
  encrypted: [
    "notes",
    "qrShippingContact",
    "ownerName",
    "contactPerson",
    "contactInfo",
    "name",
    "city",
    "zone",
    "address",
    "type",
    "paymentRails",
  ],
  searchKeys: ["notes", "name", "city", "zone", "address"],
  clear: ["visitStatus", "qrDeliveryStatus", "tags", "tagHashes"],
  blankWith: {
    notes: "",
    qrShippingContact: "",
    ownerName: "",
    contactPerson: "",
    contactInfo: "",
    name: "",
    city: "",
    zone: "",
    address: "",
    type: "",
    paymentRails: "[]",
  },
};

// EVENT: encrypt the identifying content (title/city/venue/type/url/tier/
// costTier) and the people-bearing arrays (speakers/sponsors/expectedAttendees)
// alongside notes + researchNotes. Only date + status + preOrPost + tagHashes
// stay cleartext so the calendar cron/filters keep working. City grouping +
// title search are CLIENT-SIDE on decrypted records.
const event: ModelFieldSplit = {
  encrypted: [
    "notes",
    "researchNotes",
    "title",
    "city",
    "venue",
    "type",
    "url",
    "tier",
    "costTier",
    "speakers",
    "sponsors",
    "expectedAttendees",
  ],
  searchKeys: ["notes", "researchNotes", "title", "city", "venue"],
  clear: ["date", "status", "preOrPost", "tags", "tagHashes"],
  blankWith: {
    notes: "",
    researchNotes: "",
    title: "",
    city: "",
    venue: "",
    type: "",
    url: "",
    tier: "",
    costTier: "",
    speakers: "[]",
    sponsors: "[]",
    expectedAttendees: "[]",
  },
};

const route: ModelFieldSplit = {
  // Route "notes" live per-stop; the top-level route has no single notes field,
  // so for now the only top-level free text is none — keep the split declared so
  // the engine can be extended to per-stop notes later without a schema change.
  encrypted: [],
  searchKeys: [],
  clear: ["name", "city", "status", "date", "tags", "tagHashes"],
  blankWith: {},
};

// NOMAD RESPONSE / FOUNDER LEAD ----------------------------------------------
// NOTE: these public research surveys are deliberately NOT in CONTENT_SCHEMA.
// Their Mongoose models carry no `enc` scaffold; the server stores them
// CLEARTEXT and serves them operator-only (GET is gated, POST is public). The
// bridge therefore exposes them READ-ONLY as a straight pass-through (see
// DataLayer.listReadonly / getReadonly) and never routes them through the
// encrypt/decrypt path. Keeping them out of CONTENT_SCHEMA is what makes this
// schema byte-identical with the Nest web app's contentSchema.ts.

export const CONTENT_SCHEMA: Record<CrmModel, ModelFieldSplit> = {
  person,
  task,
  company,
  merchant,
  event,
  route,
};

// Convenience: the encrypted field list for a model.
export function encryptedFields(model: CrmModel): string[] {
  return CONTENT_SCHEMA[model].encrypted;
}

// Convenience: the fuzzy-search keys for a model.
export function searchKeys(model: CrmModel): string[] {
  return CONTENT_SCHEMA[model].searchKeys;
}
