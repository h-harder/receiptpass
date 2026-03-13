/**
 * auth.ts
 * API key management using Workers KV.
 * Keys are stored as: `apikey:{key}` → JSON metadata
 */

import type { Env } from "./index";
import { jsonResponse } from "./utils";

export interface KeyMetadata {
  label: string;
  created: string;
  requests: number;
  lastUsed?: string;
  disabled?: boolean;
}

export interface AuthResult {
  valid: boolean;
  error?: string;
  apiKey?: string;
  metadata?: KeyMetadata;
}

// ─── Create a new API key ─────────────────────────────────────────────────────

export async function createApiKey(label: string, env: Env): Promise<Response> {
  // Generate a random key with "wpk_" prefix
  const rawKey = Array.from(crypto.getRandomValues(new Uint8Array(24)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const apiKey = `wpk_${rawKey}`;

  const metadata: KeyMetadata = {
    label: label.slice(0, 100),
    created: new Date().toISOString(),
    requests: 0,
  };

  // Store in KV if available; otherwise return a test key
  if (env.PASS_KEYS) {
    await env.PASS_KEYS.put(`apikey:${apiKey}`, JSON.stringify(metadata), {
      // Keys don't expire by default — add expirationTtl here for rotating keys
    });
  }

  return jsonResponse(
    {
      apiKey,
      label,
      created: metadata.created,
      message: "Store this key securely — it will not be shown again",
    },
    201
  );
}

// ─── Validate an incoming API key ─────────────────────────────────────────────

export async function validateApiKey(request: Request, env: Env): Promise<AuthResult> {
  // Accept key from X-API-Key header OR Authorization: Bearer <key>
  const xKey = request.headers.get("X-API-Key");
  const authHeader = request.headers.get("Authorization");
  const bearerKey = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : null;

  const apiKey = xKey ?? bearerKey ?? null;

  if (!apiKey) {
    return {
      valid: false,
      error: "Missing API key. Provide via X-API-Key header or Authorization: Bearer <key>",
    };
  }

  // If KV is not bound (e.g., local dev without KV), accept test_ and wpk_ prefixed keys
  if (!env.PASS_KEYS) {
    if (apiKey.startsWith("wpk_") || apiKey.startsWith("test_")) {
      return { valid: true, apiKey };
    }
    return { valid: false, error: "Invalid API key format" };
  }

  // Look up key in KV
  const stored = await env.PASS_KEYS.get(`apikey:${apiKey}`);
  if (!stored) {
    return { valid: false, error: "Invalid or revoked API key" };
  }

  let metadata: KeyMetadata;
  try {
    metadata = JSON.parse(stored) as KeyMetadata;
  } catch {
    return { valid: false, error: "Corrupted key metadata" };
  }

  if (metadata.disabled) {
    return { valid: false, error: "API key has been disabled" };
  }

  // Update usage stats — fire-and-forget (don't await so we don't slow the request)
  metadata.requests += 1;
  metadata.lastUsed = new Date().toISOString();
  env.PASS_KEYS.put(`apikey:${apiKey}`, JSON.stringify(metadata)).catch(() => {});

  return { valid: true, apiKey, metadata };
}
