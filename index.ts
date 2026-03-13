/**
 * Wallet Receipt Pass API
 * Cloudflare Worker — generates Apple Wallet (.pkpass) and Google Wallet (JWT) passes
 * for receipts. Supports single and bulk generation.
 */

import { corsHeaders, jsonResponse, errorResponse } from "./utils";
import { generatePkpass } from "./apple-pass";
import { generateGooglePassJwt } from "./google-pass";
import { validateApiKey, createApiKey } from "./auth";

export interface Env {
  PASS_KEYS: KVNamespace;
  RATE_LIMIT: KVNamespace;
  // Apple Wallet secrets (set via: wrangler secret put <NAME>)
  APPLE_PASS_TYPE_IDENTIFIER: string; // e.g. "pass.com.yourorg.receipt"
  APPLE_TEAM_IDENTIFIER: string;      // 10-char Apple Team ID
  APPLE_CERT_P12_B64: string;         // Base64-encoded .p12 certificate
  APPLE_CERT_PASSWORD: string;        // Password for the .p12
  APPLE_WWDR_CERT_B64: string;        // Base64-encoded Apple WWDR G4 cert
  // Google Wallet secrets
  GOOGLE_ISSUER_ID: string;
  GOOGLE_SERVICE_ACCOUNT_EMAIL: string;
  GOOGLE_SERVICE_ACCOUNT_KEY: string; // PEM private key
}

// ─── Pass Data Types ──────────────────────────────────────────────────────────

export interface LineItem {
  description: string;
  quantity?: number;
  unitPrice?: number;
  total: number;
}

export interface ReceiptPassData {
  /** Unique receipt/order ID */
  orderId: string;
  /** Merchant / store name */
  merchantName: string;
  /** Date of purchase — ISO 8601 or human-readable */
  purchaseDate: string;
  /** Total amount paid */
  total: number;
  /** Currency code, e.g. "USD" */
  currency?: string;
  /** Optional itemized line items */
  lineItems?: LineItem[];
  /** Optional: loyalty points earned */
  pointsEarned?: number;
  /** Optional: last 4 of payment card */
  cardLast4?: string;
  /** Optional: payment method label */
  paymentMethod?: string;
  /** Optional: store/location address */
  storeAddress?: string;
  /** Optional: support URL shown on back */
  supportUrl?: string;
  /** Optional: return policy text shown on back */
  returnPolicy?: string;
  /** Background color as CSS rgb() */
  backgroundColor?: string;
  /** Foreground/text color as CSS rgb() */
  foregroundColor?: string;
  /** Logo text shown beside logo area */
  logoText?: string;
  /** Base64-encoded icon PNG (required for real signed passes) */
  iconBase64?: string;
  /** Base64-encoded logo PNG */
  logoBase64?: string;
  /** Optional web service URL for push updates */
  webServiceURL?: string;
  /** Auth token for web service */
  authenticationToken?: string;
}

export interface BulkPassRequest {
  platform: "apple" | "google" | "both";
  receipts: ReceiptPassData[];
}

// ─── Router ──────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Handle CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const url = new URL(request.url);
    const { pathname } = url;

    try {
      // Public routes (no auth)
      if (pathname === "/" || pathname === "") return handleRoot();
      if (pathname === "/health" && request.method === "GET") return handleHealth();
      if (pathname === "/api/keys" && request.method === "POST") return handleCreateKey(request, env);

      // Protected routes
      const authResult = await validateApiKey(request, env);
      if (!authResult.valid) {
        return errorResponse(authResult.error ?? "Unauthorized", 401);
      }

      // Rate limiting
      const limited = await checkRateLimit(authResult.apiKey!, env);
      if (limited) {
        return errorResponse("Rate limit exceeded. Max 120 requests/minute.", 429);
      }

      // Pass generation routes
      if (pathname === "/api/passes/receipt" && request.method === "POST") {
        return handleSingleReceipt(request, env);
      }
      if (pathname === "/api/passes/bulk" && request.method === "POST") {
        return handleBulkReceipts(request, env);
      }
      if (pathname === "/api/passes/preview" && request.method === "POST") {
        return handlePreview(request);
      }

      return errorResponse("Not Found", 404);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Internal Server Error";
      console.error("Worker error:", message, err);
      return errorResponse(`Internal Server Error: ${message}`, 500);
    }
  },
} satisfies ExportedHandler<Env>;

// ─── Handlers ─────────────────────────────────────────────────────────────────

function handleRoot(): Response {
  return jsonResponse({
    name: "Wallet Receipt Pass API",
    version: "1.0.0",
    description: "Generate Apple Wallet and Google Wallet receipt passes",
    endpoints: {
      "POST /api/keys": "Create a new API key",
      "POST /api/passes/receipt": "Generate a single receipt pass",
      "POST /api/passes/bulk": "Generate up to 50 receipt passes",
      "POST /api/passes/preview": "Preview pass JSON without generating file",
      "GET /health": "Health check",
    },
    platforms: ["apple", "google", "both"],
    docs: "https://github.com/your-org/wallet-pass-api",
  });
}

function handleHealth(): Response {
  return jsonResponse({ status: "ok", timestamp: new Date().toISOString() });
}

async function handleCreateKey(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ label?: string }>().catch(() => ({}));
  return createApiKey(body.label ?? "Unnamed Key", env);
}

async function handleSingleReceipt(request: Request, env: Env): Promise<Response> {
  const body = await request.json<{ platform?: string; receipt: ReceiptPassData }>().catch(() => null);
  if (!body?.receipt) {
    return errorResponse("Request body must include a `receipt` object", 400);
  }

  const platform = (body.platform ?? "apple") as "apple" | "google" | "both";
  const validation = validateReceiptData(body.receipt);
  if (!validation.valid) {
    return errorResponse(`Invalid receipt data: ${validation.error}`, 400);
  }

  if (platform === "apple") {
    const pkpass = await generatePkpass(body.receipt, env);
    return new Response(pkpass, {
      headers: {
        ...corsHeaders,
        "Content-Type": "application/vnd.apple.pkpass",
        "Content-Disposition": `attachment; filename="receipt-${body.receipt.orderId}.pkpass"`,
      },
    });
  }

  if (platform === "google") {
    const result = await generateGooglePassJwt(body.receipt, env);
    return jsonResponse(result);
  }

  // "both" — return JSON with both
  const [pkpassBuffer, googleResult] = await Promise.all([
    generatePkpass(body.receipt, env),
    generateGooglePassJwt(body.receipt, env),
  ]);
  const pkpassBase64 = bufferToBase64(pkpassBuffer);
  return jsonResponse({
    apple: { format: "pkpass", base64: pkpassBase64, mimeType: "application/vnd.apple.pkpass" },
    google: googleResult,
  });
}

async function handleBulkReceipts(request: Request, env: Env): Promise<Response> {
  const body = await request.json<BulkPassRequest>().catch(() => null);
  if (!body?.receipts || !Array.isArray(body.receipts)) {
    return errorResponse("Request body must include a `receipts` array", 400);
  }
  if (body.receipts.length === 0) {
    return errorResponse("`receipts` array cannot be empty", 400);
  }
  if (body.receipts.length > 50) {
    return errorResponse("Maximum 50 receipts per bulk request", 400);
  }

  const platform = (body.platform ?? "apple") as "apple" | "google" | "both";

  const results = await Promise.allSettled(
    body.receipts.map(async (receipt, index) => {
      const validation = validateReceiptData(receipt);
      if (!validation.valid) {
        throw new Error(`Receipt[${index}] (${receipt.orderId}): ${validation.error}`);
      }

      if (platform === "apple") {
        const pkpass = await generatePkpass(receipt, env);
        return {
          orderId: receipt.orderId,
          platform: "apple",
          format: "pkpass",
          base64: bufferToBase64(pkpass),
          mimeType: "application/vnd.apple.pkpass",
        };
      }

      if (platform === "google") {
        const result = await generateGooglePassJwt(receipt, env);
        return { orderId: receipt.orderId, platform: "google", ...result };
      }

      // both
      const [pkpass, googleResult] = await Promise.all([
        generatePkpass(receipt, env),
        generateGooglePassJwt(receipt, env),
      ]);
      return {
        orderId: receipt.orderId,
        apple: { format: "pkpass", base64: bufferToBase64(pkpass), mimeType: "application/vnd.apple.pkpass" },
        google: googleResult,
      };
    })
  );

  const succeeded = results
    .filter((r): r is PromiseFulfilledResult<unknown> => r.status === "fulfilled")
    .map((r) => r.value);

  const failed = results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r, i) => ({ index: i, error: r.reason?.message ?? "Unknown error" }));

  return jsonResponse({
    total: body.receipts.length,
    succeeded: succeeded.length,
    failed: failed.length,
    passes: succeeded,
    errors: failed,
  });
}

async function handlePreview(request: Request): Promise<Response> {
  const body = await request.json<{ receipt: ReceiptPassData }>().catch(() => null);
  if (!body?.receipt) return errorResponse("Missing `receipt` in body", 400);

  const validation = validateReceiptData(body.receipt);
  if (!validation.valid) return errorResponse(validation.error!, 400);

  return jsonResponse({ valid: true, passJson: buildPassJson(body.receipt) });
}

// ─── Validation ───────────────────────────────────────────────────────────────

function validateReceiptData(data: ReceiptPassData): { valid: boolean; error?: string } {
  if (!data.orderId?.trim()) return { valid: false, error: "orderId is required" };
  if (!data.merchantName?.trim()) return { valid: false, error: "merchantName is required" };
  if (!data.purchaseDate?.trim()) return { valid: false, error: "purchaseDate is required" };
  if (typeof data.total !== "number" || isNaN(data.total)) {
    return { valid: false, error: "total must be a number" };
  }
  return { valid: true };
}

// ─── Pass JSON builder (shared with apple-pass.ts) ────────────────────────────

export function buildPassJson(data: ReceiptPassData): Record<string, unknown> {
  const currency = data.currency ?? "USD";
  const totalFormatted = formatCurrency(data.total, currency);

  const backFields: Array<{ key: string; label: string; value: string; attributedValue?: string }> = [
    { key: "orderId", label: "Order ID", value: data.orderId },
    { key: "date", label: "Purchase Date", value: data.purchaseDate },
  ];

  if (data.lineItems?.length) {
    const itemLines = data.lineItems
      .map((li) => `${li.description}${li.quantity ? ` ×${li.quantity}` : ""}: ${formatCurrency(li.total, currency)}`)
      .join("\n");
    backFields.push({ key: "items", label: "Items", value: itemLines });
  }

  if (data.paymentMethod || data.cardLast4) {
    const payLabel = [data.paymentMethod, data.cardLast4 ? `···· ${data.cardLast4}` : ""]
      .filter(Boolean)
      .join(" ");
    backFields.push({ key: "payment", label: "Payment", value: payLabel });
  }

  if (data.storeAddress) {
    backFields.push({ key: "store", label: "Store", value: data.storeAddress });
  }

  if (data.returnPolicy) {
    backFields.push({ key: "returns", label: "Return Policy", value: data.returnPolicy });
  }

  if (data.supportUrl) {
    backFields.push({
      key: "support",
      label: "Support",
      value: data.supportUrl,
      attributedValue: `<a href='${data.supportUrl}'>Contact Support</a>`,
    });
  }

  const passJson: Record<string, unknown> = {
    formatVersion: 1,
    passTypeIdentifier: "pass.com.example.receipt",
    serialNumber: `RCPT-${data.orderId}`,
    teamIdentifier: "XXXXXXXXXX",
    organizationName: data.merchantName,
    description: `Receipt from ${data.merchantName}`,
    logoText: data.logoText ?? data.merchantName,
    backgroundColor: data.backgroundColor ?? "rgb(15, 23, 42)",
    foregroundColor: data.foregroundColor ?? "rgb(255, 255, 255)",
    labelColor: data.foregroundColor ?? "rgb(255, 255, 255)",
    generic: {
      primaryFields: [
        { key: "total", label: "TOTAL", value: totalFormatted },
      ],
      secondaryFields: [
        { key: "merchant", label: "FROM", value: data.merchantName },
        { key: "date", label: "DATE", value: data.purchaseDate },
      ],
      auxiliaryFields: [
        ...(data.pointsEarned != null
          ? [{ key: "points", label: "POINTS EARNED", value: String(data.pointsEarned) }]
          : []),
        ...(data.cardLast4
          ? [{ key: "card", label: "PAID WITH", value: `···· ${data.cardLast4}` }]
          : []),
      ],
      backFields,
    },
    barcode: {
      format: "PKBarcodeFormatQR",
      message: data.orderId,
      messageEncoding: "iso-8859-1",
      altText: `Order #${data.orderId}`,
    },
    barcodes: [
      {
        format: "PKBarcodeFormatQR",
        message: data.orderId,
        messageEncoding: "iso-8859-1",
        altText: `Order #${data.orderId}`,
      },
    ],
    sharingProhibited: false,
  };

  // Attach web service if provided (enables push update invalidation)
  if (data.webServiceURL && data.authenticationToken) {
    passJson.webServiceURL = data.webServiceURL;
    passJson.authenticationToken = data.authenticationToken;
  }

  return passJson;
}

// ─── Rate limiting ─────────────────────────────────────────────────────────────

async function checkRateLimit(apiKey: string, env: Env): Promise<boolean> {
  if (!env.RATE_LIMIT) return false;
  const window = Math.floor(Date.now() / 60_000);
  const key = `rl:${apiKey}:${window}`;
  try {
    const current = await env.RATE_LIMIT.get(key);
    const count = current ? parseInt(current, 10) : 0;
    if (count >= 120) return true; // exceeded
    await env.RATE_LIMIT.put(key, String(count + 1), { expirationTtl: 120 });
    return false;
  } catch {
    return false; // fail open
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatCurrency(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(amount);
  } catch {
    return `${currency} ${amount.toFixed(2)}`;
  }
}

function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
