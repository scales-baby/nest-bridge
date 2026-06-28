// Bridge — the CRM data layer: encrypt-on-write / decrypt-on-read.
//
// READ:  fetch ciphertext from the Nest REST API → hydrateRecord() with the DEK
//        locally → return plaintext to the MCP caller (Claude).
// WRITE: take the caller's plaintext → buildWritePayload() encrypts the
//        sensitive fields into an `enc` blob + blanks plaintext locally → POST
//        the ciphertext to the Nest API (the server stamps ownerId, stores the
//        blob, never sees plaintext or the DEK).
//
// When the account is UNENCRYPTED (no DEK), everything is a pass-through — the
// server stores/returns plaintext exactly as the web app does.

import { NestClient } from "./nestClient";
import {
  buildWritePayload,
  hydrateRecord,
  type CrmModel,
  type StoredRecord,
} from "./crypto";

// Map a CrmModel to its REST collection path.
const PATHS: Record<CrmModel, string> = {
  person: "/api/people",
  company: "/api/companies",
  task: "/api/tasks",
  event: "/api/events",
  merchant: "/api/merchants",
  route: "/api/routes",
};

export interface Vault {
  encrypted: boolean;
  dek: Uint8Array | null;
  dekVersion: number;
}

export class DataLayer {
  constructor(private client: NestClient, private vault: Vault) {}

  private path(model: CrmModel): string {
    return PATHS[model];
  }

  // --- READS ---------------------------------------------------------------

  async list(
    model: CrmModel,
    query: Record<string, string | number | undefined> = {}
  ): Promise<Record<string, unknown>[]> {
    const qs = Object.entries(query)
      .filter(([, v]) => v !== undefined && v !== "")
      .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
      .join("&");
    const path = qs ? `${this.path(model)}?${qs}` : this.path(model);
    const rows = (await this.client.get<Record<string, unknown>[]>(path)) ?? [];
    return Promise.all(rows.map((r) => this.decrypt(model, r)));
  }

  async get(
    model: CrmModel,
    id: string
  ): Promise<Record<string, unknown> | null> {
    const row = await this.client.get<Record<string, unknown> | null>(
      `${this.path(model)}/${id}`
    );
    if (!row) return null;
    return this.decrypt(model, row);
  }

  private async decrypt(
    model: CrmModel,
    row: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    // hydrateRecord is a no-op for plaintext docs (no `enc`) and for unencrypted
    // accounts (dek=null leaves blanks). With the DEK it merges decrypted
    // content back over the cleartext metadata.
    try {
      return (await hydrateRecord(
        model,
        this.vault.dek,
        row as StoredRecord
      )) as Record<string, unknown>;
    } catch {
      // A single corrupt blob shouldn't blank the whole call — return as-is.
      return row;
    }
  }

  // --- WRITES --------------------------------------------------------------

  // Create: `fields` is the caller's plaintext. We encrypt locally (if the
  // account is encrypted) and POST ciphertext. Returns the created record,
  // decrypted back for the caller.
  async create(
    model: CrmModel,
    fields: Record<string, unknown>
  ): Promise<Record<string, unknown> | null> {
    const payload = await buildWritePayload(
      model,
      {
        encrypted: this.vault.encrypted,
        dek: this.vault.dek,
        dekVersion: this.vault.dekVersion,
      },
      fields,
      fields
    );
    const created = await this.client.post<Record<string, unknown> | null>(
      this.path(model),
      payload
    );
    if (!created) return null;
    return this.decrypt(model, created);
  }

  // Update: PATCH. For an encrypted account, `enc` is ONE per-doc blob, so we
  // must re-encrypt the COMPLETE sensitive set. We fetch + decrypt the current
  // record, merge the caller's changes on top, then build the write from the
  // merged full record (sensitive) + the caller's changes (cleartext only).
  async update(
    model: CrmModel,
    id: string,
    changes: Record<string, unknown>
  ): Promise<Record<string, unknown> | null> {
    let payload: Record<string, unknown>;
    if (this.vault.encrypted && this.vault.dek) {
      const current = await this.get(model, id); // decrypted
      const merged = { ...(current ?? {}), ...changes };
      payload = await buildWritePayload(
        model,
        {
          encrypted: true,
          dek: this.vault.dek,
          dekVersion: this.vault.dekVersion,
        },
        merged,
        changes
      );
    } else {
      // Unencrypted: pass the caller's changes through.
      payload = await buildWritePayload(
        model,
        { encrypted: false, dek: null },
        changes,
        changes
      );
    }
    const updated = await this.client.patch<Record<string, unknown> | null>(
      `${this.path(model)}/${id}`,
      payload
    );
    if (!updated) return null;
    return this.decrypt(model, updated);
  }

  // Convenience: mark a task done (metadata-only write, never touches content).
  async completeTask(id: string): Promise<Record<string, unknown> | null> {
    const updated = await this.client.patch<Record<string, unknown> | null>(
      `${this.path("task")}/${id}`,
      { status: "done" }
    );
    if (!updated) return null;
    return this.decrypt("task", updated);
  }

  async digest(): Promise<unknown> {
    return this.client.get("/api/digest");
  }
}
