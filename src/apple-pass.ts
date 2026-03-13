/**
 * apple-pass.ts
 * Builds a .pkpass file (ZIP archive) containing:
 *   pass.json    — structured pass data
 *   manifest.json — SHA-1 hashes of every file in the archive
 *   signature    — PKCS#7 detached signature of manifest.json
 *   icon.png     — pass icon (1x)
 *   icon@2x.png  — pass icon (2x, optional)
 *   logo.png     — logo shown on strip (optional)
 *
 * SIGNING NOTE:
 *   WebCrypto (available in Workers) supports RSA-PSS and ECDSA but NOT the
 *   full PKCS#7/CMS format Apple requires. Two production options:
 *
 *   Option A — Signing microservice:
 *     A tiny Node.js sidecar (using `node-forge` or `@signpass/signpass`) that
 *     your Worker calls via a Cloudflare Service Binding or plain fetch.
 *
 *   Option B — Pre-compute signature template:
 *     Generate a "stub" signature with your cert that works for the static
 *     parts and re-sign only the manifest at runtime using a Rust/WASM PKCS7
 *     implementation compiled for Workers.
 *
 *   This file generates a structurally correct .pkpass (valid ZIP with proper
 *   pass.json and manifest) with a stub signature so the file can be tested
 *   end-to-end. Once you wire up real PKCS#7 signing the same ZIP is used.
 */

import { buildPassJson, type Env, type ReceiptPassData } from "./index";

// ─── Public API ───────────────────────────────────────────────────────────────

export async function generatePkpass(data: ReceiptPassData, env: Env): Promise<ArrayBuffer> {
  // 1. Build pass.json with real certs/identifiers if available
  const passJson = buildPassJsonWithEnv(data, env);
  const passJsonBytes = new TextEncoder().encode(JSON.stringify(passJson, null, 2));

  // 2. Collect all files for the archive
  const files: Record<string, Uint8Array> = {};
  files["pass.json"] = passJsonBytes;

  // Add icon images (use provided base64 or fall back to embedded placeholder)
  files["icon.png"] = data.iconBase64 ? base64ToBytes(data.iconBase64) : PLACEHOLDER_ICON;
  files["icon@2x.png"] = files["icon.png"]; // same image for simplicity

  if (data.logoBase64) {
    files["logo.png"] = base64ToBytes(data.logoBase64);
    files["logo@2x.png"] = files["logo.png"];
  }

  // 3. Build manifest (SHA-1 of every file)
  const manifest: Record<string, string> = {};
  for (const [name, bytes] of Object.entries(files)) {
    manifest[name] = await sha1Hex(bytes);
  }
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest, null, 2));
  files["manifest.json"] = manifestBytes;

  // 4. Signature — stub for development; replace with real PKCS#7 in production
  files["signature"] = await signManifest(manifestBytes, env);

  // 5. Pack into a ZIP / .pkpass
  return buildZip(files);
}

// ─── Pass JSON with real env values ──────────────────────────────────────────

function buildPassJsonWithEnv(data: ReceiptPassData, env: Env): Record<string, unknown> {
  const base = buildPassJson(data);

  // Override with real Apple credentials if configured
  if (env.APPLE_PASS_TYPE_IDENTIFIER) {
    base.passTypeIdentifier = env.APPLE_PASS_TYPE_IDENTIFIER;
  }
  if (env.APPLE_TEAM_IDENTIFIER) {
    base.teamIdentifier = env.APPLE_TEAM_IDENTIFIER;
  }

  return base;
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/**
 * In production: call your signing microservice or implement PKCS#7 via WASM.
 * Here we return an empty signature so the ZIP structure is correct and
 * testable — iOS will reject unsigned passes but the file format is valid.
 */
async function signManifest(manifestBytes: Uint8Array, env: Env): Promise<Uint8Array> {
  // If a signing endpoint is configured, call it
  if (env.APPLE_CERT_P12_B64 && env.APPLE_CERT_PASSWORD && env.APPLE_WWDR_CERT_B64) {
    // TODO: Call your signing microservice:
    //   const resp = await fetch("https://sign.internal/pkcs7", {
    //     method: "POST",
    //     headers: { "Content-Type": "application/octet-stream" },
    //     body: manifestBytes,
    //   });
    //   return new Uint8Array(await resp.arrayBuffer());
    console.log("PKCS#7 signing not yet implemented — returning stub signature");
  }
  // Stub: empty PKCS#7 placeholder (passes won't install on real devices)
  return new Uint8Array(0);
}

// ─── ZIP builder (pure JS, no dependencies) ───────────────────────────────────

function buildZip(files: Record<string, Uint8Array>): ArrayBuffer {
  // Build local file entries
  const entries: Array<{
    nameBytes: Uint8Array;
    data: Uint8Array;
    crc: number;
    localOffset: number;
    localHeader: Uint8Array;
  }> = [];

  let offset = 0;

  for (const [name, data] of Object.entries(files)) {
    const nameBytes = new TextEncoder().encode(name);
    const crc = crc32(data);
    const ts = dosDateTime();

    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    lv.setUint32(0, 0x04034b50, true); // local file header signature
    lv.setUint16(4, 20, true);          // version needed: 2.0
    lv.setUint16(6, 0, true);           // general purpose flags
    lv.setUint16(8, 0, true);           // compression: STORED
    lv.setUint16(10, ts.time, true);
    lv.setUint16(12, ts.date, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true); // compressed size
    lv.setUint32(22, data.length, true); // uncompressed size
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);           // extra field length
    localHeader.set(nameBytes, 30);

    entries.push({ nameBytes, data, crc, localOffset: offset, localHeader });
    offset += localHeader.length + data.length;
  }

  // Build central directory entries
  const centralDirs: Uint8Array[] = [];
  for (const e of entries) {
    const ts = dosDateTime();
    const cd = new Uint8Array(46 + e.nameBytes.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);  // central directory signature
    cv.setUint16(4, 20, true);           // version made by
    cv.setUint16(6, 20, true);           // version needed
    cv.setUint16(8, 0, true);
    cv.setUint16(10, 0, true);           // STORED
    cv.setUint16(12, ts.time, true);
    cv.setUint16(14, ts.date, true);
    cv.setUint32(16, e.crc, true);
    cv.setUint32(20, e.data.length, true);
    cv.setUint32(24, e.data.length, true);
    cv.setUint16(28, e.nameBytes.length, true);
    cv.setUint16(30, 0, true);           // extra length
    cv.setUint16(32, 0, true);           // comment length
    cv.setUint16(34, 0, true);           // disk number start
    cv.setUint16(36, 0, true);           // internal attrs
    cv.setUint32(38, 0, true);           // external attrs
    cv.setUint32(42, e.localOffset, true);
    cd.set(e.nameBytes, 46);
    centralDirs.push(cd);
  }

  // End of central directory record
  const cdSize = centralDirs.reduce((s, c) => s + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);   // EOCD signature
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);      // central dir offset
  ev.setUint16(20, 0, true);

  // Concatenate everything
  const parts: Uint8Array[] = [
    ...entries.flatMap((e) => [e.localHeader, e.data]),
    ...centralDirs,
    eocd,
  ];
  const totalSize = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(totalSize);
  let pos = 0;
  for (const p of parts) {
    result.set(p, pos);
    pos += p.length;
  }
  return result.buffer;
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

async function sha1Hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? (0xedb88320 ^ (crc >>> 1)) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(): { time: number; date: number } {
  const d = new Date();
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

function base64ToBytes(b64: string): Uint8Array {
  // Strip data URL prefix if present
  const clean = b64.replace(/^data:[^;]+;base64,/, "");
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─── Placeholder icon (1×1 transparent PNG) ──────────────────────────────────

const PLACEHOLDER_ICON = base64ToBytes(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
);
