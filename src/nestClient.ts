// Bridge — typed HTTP client for the Nest REST API.
//
// Talks to nest.scales.baby (or a configured URL) using the user's SCOPED API
// KEY as a Bearer token. The server returns CIPHERTEXT for encrypted accounts
// (the `enc` blob + blanked plaintext columns) — decryption happens locally in
// the bridge with the DEK. On writes the bridge sends ciphertext we built
// locally. The server never sees the DEK, the password, or plaintext.
//
// trailingSlash:true on Nest → every API path MUST end in "/" (a no-slash path
// 308-redirects and can drop a POST body).

import type { WrappedDekRecord } from "./crypto/envelope";

export interface NestClientConfig {
  apiUrl: string; // e.g. https://nest.scales.baby
  apiKey: string; // nest_<prefix>_<secret>
}

interface Envelope<T> {
  data: T | null;
  error: string | null;
}

export class NestApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "NestApiError";
    this.status = status;
  }
}

export class NestClient {
  private base: string;
  private key: string;

  constructor(cfg: NestClientConfig) {
    // Normalise: strip a trailing slash from the base; we add per-path slashes.
    this.base = cfg.apiUrl.replace(/\/+$/, "");
    this.key = cfg.apiKey;
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.key}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    };
  }

  // Ensure exactly one trailing slash (before any query string).
  private url(path: string): string {
    const [p, q] = path.split("?");
    const withSlash = p.endsWith("/") ? p : `${p}/`;
    return `${this.base}${withSlash}${q ? `?${q}` : ""}`;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const res = await fetch(this.url(path), {
      method,
      headers: this.headers(),
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "follow",
    });
    let json: Envelope<T> | null = null;
    const text = await res.text();
    try {
      json = text ? (JSON.parse(text) as Envelope<T>) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const msg = json?.error || text || res.statusText;
      throw new NestApiError(msg || `request_failed_${res.status}`, res.status);
    }
    if (json && json.error) {
      throw new NestApiError(json.error, res.status);
    }
    // Some endpoints return the data directly under `data`.
    return (json ? (json.data as T) : (null as unknown as T));
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }
  post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("POST", path, body);
  }
  patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>("PATCH", path, body);
  }

  // --- bridge unlock: fetch the password-wrapped DEK blob ------------------
  async getBridgeWrap(): Promise<{
    encState: string;
    scopes: string[];
    hasPasswordWrap: boolean;
    wrap: WrappedDekRecord | null;
  }> {
    return this.get("/api/keys/bridge-wrap");
  }
}
