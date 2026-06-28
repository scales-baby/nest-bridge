// Crypto round-trip proof: the bridge's crypto must be byte-identical to the
// Nest web client's. We exercise the SAME modules the bridge ships in dist/.
//
// 1) Generate a DEK (web client primitive).
// 2) Derive a NEW password KEK (derivePasswordKekNew) + wrap the DEK — exactly
//    what the browser POSTs to /api/keys/wrap.
// 3) Feed that wrap + the password into the BRIDGE's unlockDekWithPassword →
//    assert it recovers the identical DEK bytes.
// 4) Encrypt a Person via buildWritePayload (web write path) → decrypt via
//    hydrateRecord (bridge read path) → assert plaintext round-trips and the
//    server-bound payload has blanked plaintext + an enc blob.

import { generateDek } from "../dist/crypto/primitives.js";
import { wrapDek, encryptContent } from "../dist/crypto/envelope.js";
import { derivePasswordKekNew } from "../dist/crypto/kek/password.js";
import { buildWritePayload, hydrateRecord } from "../dist/crypto/crmData.js";
import { unlockDekWithPassword } from "../dist/crypto.js";

function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

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

const PASSWORD = "correct horse battery staple 42";

// 1) DEK
const dek = generateDek();
ok("DEK is 32 bytes", dek.length === 32);

// 2) password KEK + wrap (browser path)
const kekRes = await derivePasswordKekNew(PASSWORD);
const wrapped = await wrapDek(kekRes.kek, dek, {
  method: "password",
  binding: "password",
  kdfSalt: kekRes.kdfSalt,
  kdf: kekRes.kdf,
  dekVersion: 1,
});
// shape the server stores → the bridge-wrap endpoint returns this same shape
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

// 3) bridge unlock re-derives the SAME DEK (same password → same DEK)
const { dek: dek2 } = await unlockDekWithPassword(PASSWORD, wrapRecord);
ok("bridge re-derives identical DEK", eq(dek, dek2));

// wrong password fails (integrity)
let threw = false;
try {
  await unlockDekWithPassword("wrong password", wrapRecord);
} catch {
  threw = true;
}
ok("wrong password rejected (GCM tag)", threw);

// 4) content round-trip: web write → bridge read
const plainPerson = {
  name: "Ada Lovelace",
  companyName: "Analytical Engines",
  role: "Mathematician",
  notes: "First programmer. Met at a salon.",
  status: "met",
  nextAction: "Send the Bernoulli notes",
  tags: ["vip", "math"],
};
const writePayload = await buildWritePayload(
  "person",
  { encrypted: true, dek, dekVersion: 1 },
  plainPerson,
  plainPerson
);
ok("write blanks plaintext name", writePayload.name === "");
ok("write blanks plaintext notes", writePayload.notes === "");
ok("write sets enc blob", !!writePayload.enc && !!writePayload.enc.ct);
ok("write sets encMigrated", writePayload.encMigrated === true);
ok("write keeps cleartext status", writePayload.status === "met");

// server "stores" the payload; bridge reads it back (simulate the stored doc)
const storedDoc = { _id: "x", ...writePayload };
const hydrated = await hydrateRecord("person", dek2, storedDoc);
ok("read recovers name", hydrated.name === plainPerson.name);
ok("read recovers notes", hydrated.notes === plainPerson.notes);
ok("read recovers nextAction", hydrated.nextAction === plainPerson.nextAction);
ok(
  "read recovers tags",
  JSON.stringify(hydrated.tags) === JSON.stringify(plainPerson.tags)
);

// locked (no DEK) read leaves content blank, never throws
const lockedRead = await hydrateRecord("person", null, storedDoc);
ok("locked read keeps name blank", lockedRead.name === "");

// independent encryptContent/decrypt sanity (envelope direct)
const env = await encryptContent(dek, { secret: "hi" }, 1);
ok("enc envelope has v/iv/ct/tag", env.v === 1 && !!env.iv && !!env.ct && !!env.tag);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
