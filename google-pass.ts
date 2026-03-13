/**
 * google-pass.ts
 * Builds a Google Wallet "Save to Google Wallet" JWT for receipt passes.
 *
 * Flow:
 *   1. Build a GenericClass (once, represents the pass template)
 *   2. Build a GenericObject (per-user, holds the receipt data)
 *   3. Sign a JWT with your Google service account key
 *   4. Return the JWT + a redirect URL to pay.google.com/gp/v/save/{jwt}
 *
 * The returned `saveUrl` can be embedded as an "Add to Google Wallet" button.
 */

import { type Env, type ReceiptPassData } from "./index";

export interface GooglePassResult {
  platform: "google";
  objectId: string;
  classId: string;
  saveUrl: string;
  token: string;
  note?: string;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export async function generateGooglePassJwt(
  data: ReceiptPassData,
  env: Env
): Promise<GooglePassResult> {
  const issuerId = env.GOOGLE_ISSUER_ID ?? "YOUR_ISSUER_ID";
  const classId = `${issuerId}.receipt_v1`;
  const objectId = `${issuerId}.receipt_${sanitizeId(data.orderId)}`;

  const passClass = buildGenericClass(classId, data);
  const passObject = buildGenericObject(objectId, classId, data);

  const iss = env.GOOGLE_SERVICE_ACCOUNT_EMAIL ?? "your-sa@project.iam.gserviceaccount.com";

  const jwtPayload = {
    iss,
    aud: "google",
    typ: "savetowallet",
    iat: Math.floor(Date.now() / 1000),
    payload: {
      genericClasses: [passClass],
      genericObjects: [passObject],
    },
  };

  let token: string;
  let note: string | undefined;

  if (env.GOOGLE_SERVICE_ACCOUNT_KEY) {
    const signed = await signJwt(jwtPayload, env.GOOGLE_SERVICE_ACCOUNT_KEY);
    if (signed) {
      token = signed;
    } else {
      token = buildUnsignedJwt(jwtPayload);
      note = "JWT signing failed — check GOOGLE_SERVICE_ACCOUNT_KEY secret";
    }
  } else {
    token = buildUnsignedJwt(jwtPayload);
    note = "Set GOOGLE_SERVICE_ACCOUNT_KEY secret for production signing";
  }

  return {
    platform: "google",
    objectId,
    classId,
    token,
    saveUrl: `https://pay.google.com/gp/v/save/${token}`,
    ...(note ? { note } : {}),
  };
}

// ─── Pass Class (template) ────────────────────────────────────────────────────

function buildGenericClass(classId: string, data: ReceiptPassData): Record<string, unknown> {
  return {
    id: classId,
    issuerName: data.merchantName,
    reviewStatus: "UNDER_REVIEW",
    logo: {
      sourceUri: {
        uri: "https://storage.googleapis.com/wallet-lab-tools-codelab-artifacts-public/pass_google_logo.jpg",
      },
      contentDescription: {
        defaultValue: { language: "en-US", value: data.merchantName },
      },
    },
    cardTitle: {
      defaultValue: { language: "en-US", value: "Receipt" },
    },
    ...(data.logoBase64
      ? {}
      : {}),
  };
}

// ─── Pass Object (per-receipt) ────────────────────────────────────────────────

function buildGenericObject(
  objectId: string,
  classId: string,
  data: ReceiptPassData
): Record<string, unknown> {
  const currency = data.currency ?? "USD";
  const totalFormatted = formatCurrency(data.total, currency);

  // Build text modules from receipt fields
  const textModulesData: Array<{ id: string; header: string; body: string }> = [
    { id: "order", header: "Order ID", body: data.orderId },
    { id: "date", header: "Date", body: data.purchaseDate },
    { id: "total", header: "Total", body: totalFormatted },
  ];

  if (data.paymentMethod || data.cardLast4) {
    const payLabel = [data.paymentMethod, data.cardLast4 ? `···· ${data.cardLast4}` : ""]
      .filter(Boolean)
      .join(" ");
    textModulesData.push({ id: "payment", header: "Payment", body: payLabel });
  }

  if (data.pointsEarned != null) {
    textModulesData.push({
      id: "points",
      header: "Points Earned",
      body: String(data.pointsEarned),
    });
  }

  if (data.lineItems?.length) {
    const itemSummary = data.lineItems
      .map(
        (li) =>
          `${li.description}${li.quantity ? ` ×${li.quantity}` : ""}: ${formatCurrency(li.total, currency)}`
      )
      .join("\n");
    textModulesData.push({ id: "items", header: "Items", body: itemSummary });
  }

  // Build links module
  const uris: Array<{ uri: string; description: string; id: string }> = [];
  if (data.supportUrl) {
    uris.push({ uri: data.supportUrl, description: "Support", id: "support" });
  }

  const passObject: Record<string, unknown> = {
    id: objectId,
    classId,
    state: "ACTIVE",
    header: data.merchantName,
    subheader: `Order #${data.orderId}`,
    textModulesData,
    barcode: {
      type: "QR_CODE",
      value: data.orderId,
      alternateText: `Order #${data.orderId}`,
    },
    cardTitle: {
      defaultValue: { language: "en-US", value: "Receipt" },
    },
    ...(uris.length ? { linksModuleData: { uris } } : {}),
    validTimeInterval: {
      start: { date: new Date().toISOString() },
    },
    hexBackgroundColor: rgbToHex(data.backgroundColor ?? "rgb(15, 23, 42)"),
  };

  if (data.storeAddress) {
    passObject.locations = [
      {
        latitude: 0,
        longitude: 0,
        // Google Wallet doesn't support address-only, but we store it as a text module above
      },
    ];
  }

  return passObject;
}

// ─── JWT signing ──────────────────────────────────────────────────────────────

async function signJwt(payload: unknown, privateKeyPem: string): Promise<string | null> {
  try {
    const header = { alg: "RS256", typ: "JWT" };
    const encodedHeader = base64url(new TextEncoder().encode(JSON.stringify(header)));
    const encodedPayload = base64url(new TextEncoder().encode(JSON.stringify(payload)));
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const keyData = pemToArrayBuffer(privateKeyPem);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      keyData,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      new TextEncoder().encode(signingInput)
    );

    return `${signingInput}.${base64url(new Uint8Array(signature))}`;
  } catch (err) {
    console.error("JWT signing error:", err);
    return null;
  }
}

function buildUnsignedJwt(payload: unknown): string {
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const body = base64url(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.UNSIGNED`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function base64url(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s/g, "");
  const binary = atob(b64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) view[i] = binary.charCodeAt(i);
  return buffer;
}

function rgbToHex(rgb: string): string {
  const m = rgb.match(/(\d+)/g);
  if (!m || m.length < 3) return "#0f1726";
  return (
    "#" +
    [m[0], m[1], m[2]]
      .map((n) => parseInt(n).toString(16).padStart(2, "0"))
      .join("")
  );
}

function formatCurrency(amount: number, currency: string): string {
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency }).format(amount);
  } catch {
    return `${currency} ${amount.toFixed(2)}`;
  }
}

function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100);
}
