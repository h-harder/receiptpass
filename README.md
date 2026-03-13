# 🧾 Wallet Receipt Pass API

A Cloudflare Worker that generates **Apple Wallet (.pkpass)** and **Google Wallet (JWT)** receipt passes on demand — with a built-in frontend UI served as Static Assets.

## Architecture

```
Browser / Your App
       │
       │  POST /api/passes/receipt  { platform, receipt }
       │  X-API-Key: wpk_xxx
       ▼
┌─────────────────────────────────────────────────────┐
│              Cloudflare Worker (Edge)               │
│                                                     │
│  src/index.ts       — router + validation           │
│  src/apple-pass.ts  — ZIP builder → .pkpass binary  │
│  src/google-pass.ts — JWT builder → save URL        │
│  src/auth.ts        — KV-backed API keys            │
│                                                     │
│  KV: PASS_KEYS      — API key storage               │
│  KV: RATE_LIMIT     — 120 req/min sliding window    │
│  Assets: /public    — built-in UI                   │
└─────────────────────────────────────────────────────┘
       │
       ├── .pkpass binary  (Apple → tap → Add to Wallet)
       └── { saveUrl }     (Google → redirect → Save to Google Wallet)
```

## Project Structure

```
wallet-pass-worker/
├── src/
│   ├── index.ts         Main router + Env types + pass.json builder
│   ├── apple-pass.ts    .pkpass ZIP generator (pure JS, no native deps)
│   ├── google-pass.ts   Google Wallet JWT builder (WebCrypto signing)
│   ├── auth.ts          API key create/validate via KV
│   └── utils.ts         CORS headers, JSON/error response helpers
├── public/
│   └── index.html       Full-featured UI (single file, no build step)
├── wrangler.jsonc        Cloudflare Worker config
└── README.md
```

## Quick Start

### 1. Install & Login
```bash
npm install -g wrangler
wrangler login
```

### 2. Create KV Namespaces
```bash
wrangler kv namespace create PASS_KEYS
wrangler kv namespace create PASS_KEYS --preview

wrangler kv namespace create RATE_LIMIT
wrangler kv namespace create RATE_LIMIT --preview
```
Copy the IDs printed into `wrangler.jsonc`.

### 3. Deploy
```bash
cd wallet-pass-worker
wrangler deploy
```
Your API + UI are now live at `https://wallet-receipt-pass-api.YOUR_SUBDOMAIN.workers.dev`

### 4. Create your first API key
```bash
curl -X POST https://YOUR_WORKER.workers.dev/api/keys \
  -H "Content-Type: application/json" \
  -d '{"label": "My App"}'
```

### 5. Generate a receipt pass
```bash
# Apple Wallet (.pkpass binary)
curl -X POST https://YOUR_WORKER.workers.dev/api/passes/receipt \
  -H "X-API-Key: wpk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "apple",
    "receipt": {
      "orderId": "ORD-001",
      "merchantName": "Acme Coffee",
      "purchaseDate": "Jan 15, 2025",
      "total": 24.99,
      "currency": "USD",
      "paymentMethod": "Visa",
      "cardLast4": "4242",
      "lineItems": [
        {"description": "Oat Latte", "quantity": 2, "total": 12.00},
        {"description": "Croissant", "quantity": 1, "total": 4.50}
      ]
    }
  }' --output receipt.pkpass

# Open receipt.pkpass on iOS → "Add to Apple Wallet"
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/keys` | Create API key |
| `POST` | `/api/passes/receipt` | Single receipt pass (apple / google / both) |
| `POST` | `/api/passes/bulk` | Batch up to 50 passes |
| `POST` | `/api/passes/preview` | Validate + preview pass.json without file |
| `GET`  | `/health` | Health check |

## Receipt Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `orderId` | string | ✅ | Unique order/receipt ID |
| `merchantName` | string | ✅ | Store/brand name |
| `purchaseDate` | string | ✅ | Date of purchase |
| `total` | number | ✅ | Amount paid |
| `currency` | string | — | ISO 4217 code (default: `USD`) |
| `lineItems` | LineItem[] | — | Itemized breakdown |
| `paymentMethod` | string | — | e.g. `"Visa"` |
| `cardLast4` | string | — | Last 4 digits |
| `pointsEarned` | number | — | Loyalty points |
| `storeAddress` | string | — | Location |
| `returnPolicy` | string | — | Text shown on back |
| `supportUrl` | string | — | Support link on back |
| `backgroundColor` | string | — | CSS `rgb(r, g, b)` |
| `foregroundColor` | string | — | CSS `rgb(r, g, b)` |
| `logoBase64` | string | — | Base64 PNG for logo |
| `iconBase64` | string | — | Base64 PNG for icon |

## Production: Apple Wallet Signing

Apple requires PKCS#7 signatures. Cloudflare Workers WebCrypto doesn't support full PKCS#7. **Two options:**

### Option A — Signing Microservice (recommended)
```bash
# Tiny Node.js sidecar using passkit-generator
npm install passkit-generator

# Your Worker calls it via Service Binding or fetch:
const sig = await fetch("https://signer.internal/pkcs7", {
  method: "POST",
  body: manifestBytes,
});
```

### Option B — Cloudflare Rust/WASM
Compile a PKCS#7 signer to WASM targeting `wasm32-unknown-unknown` and load it in the Worker. The [`rasn`](https://github.com/nickelc/rasn) crate supports this.

### Certificates you need
1. **Apple Developer account** ($99/yr) → developer.apple.com
2. Create a **Pass Type ID** (e.g. `pass.com.yourcompany.receipts`)
3. Download your **Pass Type Certificate** → export as `.p12`
4. Download **Apple WWDR G4** certificate

```bash
# Store as secrets
base64 -i PassCert.p12 | wrangler secret put APPLE_CERT_P12_B64
wrangler secret put APPLE_CERT_PASSWORD      # .p12 password
base64 -i AppleWWDRG4.cer | wrangler secret put APPLE_WWDR_CERT_B64
wrangler secret put APPLE_PASS_TYPE_IDENTIFIER  # pass.com.yourco.receipts
wrangler secret put APPLE_TEAM_IDENTIFIER        # 10-char team ID
```

## Production: Google Wallet

```bash
# Get from Google Pay & Wallet Console → Service Accounts
wrangler secret put GOOGLE_ISSUER_ID
wrangler secret put GOOGLE_SERVICE_ACCOUNT_EMAIL
wrangler secret put GOOGLE_SERVICE_ACCOUNT_KEY   # PEM private key
```

Google Wallet signing (RSASSA-PKCS1-v1_5) is **fully supported** by Cloudflare Workers WebCrypto — no sidecar needed.

## Frontend UI

The `public/index.html` is served as a Cloudflare Static Asset alongside your Worker. It includes:
- **Single Pass builder** — form → live preview → Add to Apple/Google Wallet buttons
- **Bulk Generator** — drag-and-drop JSON, auto-downloads all `.pkpass` files
- **API Docs** — ready-to-copy TypeScript examples

## Rate Limits

- 120 requests/minute per API key (configurable in `src/index.ts`)
- Uses a sliding 1-minute window in Workers KV

## License

MIT
