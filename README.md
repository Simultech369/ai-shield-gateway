# AI Shield Gateway API

**Zero-Leak PII Surrogate Shield & Cryptographic Grounding Verifier with Dual-Rail Monetization (RapidAPI + x402 on Base).**

---

## 🚀 Overview

The **AI Shield Gateway** is an automated privacy, security, and verification proxy designed for AI applications, RAG pipelines, and autonomous AI agents:

1. **Reversible PII & Secret Shield (`POST /v1/mask` & `POST /v1/unmask`):**
   - Bijectively maps sensitive data (emails, API keys, private keys, ETH/crypto addresses, IP addresses, local filesystem paths) to deterministic surrogates (`{{SURROGATE_EMAIL_1}}`, etc.).
   - Preserves co-reference across multi-turn chat messages.
   - Emits an encrypted recovery token and cryptographic SHA-256 evidence receipt with zero raw PII egress.
   - Re-hydrates original values seamlessly in LLM completions.

2. **Cryptographic Citation & Grounding Verifier (`POST /v1/verify-citations`):**
   - Verifies whether an LLM's cited quotes actually exist in source documents.
   - Distinguishes exact matches, normalized matches, line drift, and phantom hallucinations.
   - Emits tamper-evident SHA-256 grounding receipts.

---

## 💳 Dual-Rail Monetization Architecture

The API operates two parallel payment rails so you capture revenue from both Web2 developers and autonomous on-chain agents:

```
                          ┌───────────────────────────┐
                          │ Caller (Agent, Dev, App)  │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┴───────────────────────────┐
           ▼                                                        ▼
 [ Rail 1: RapidAPI Gateway ]                             [ Rail 2: x402 Base USDC ]
 • RapidAPI handles credit cards                          • Returns HTTP 402 Payment Required
 • Automatic monthly & per-call billing                   • Agent transfers $0.05 USDC on Base
 • Validates X-RapidAPI-Proxy-Secret                      • Verifies on-chain via Base RPC
           │                                                        │
           └────────────────────────────┬───────────────────────────┘
                                        ▼
                            [ AI Shield Gateway Engine ]
```

### Rail 1: Web2 Developers (RapidAPI)
- Callers pass header: `X-RapidAPI-Proxy-Secret: <secret>` and `X-RapidAPI-User: <user>`.
- RapidAPI bills users ($19/mo or $0.03/call) and pays out directly to your PayPal or Bank.

### Rail 2: Web3 Autonomous AI Agents (x402 Protocol)
- If no auth is provided, the API returns:
  ```http
  HTTP/1.1 402 Payment Required
  X-Accept-Currency: USDC
  X-Price: 0.05
  X-Pay-To: 0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7
  X-Chain-ID: 8453
  X-Token-Contract: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913
  ```
- Autonomous AI agents (Coinbase AgentKit, LangChain, Eliza) send $0.05 USDC on Base, attach `X-Payment-Tx: <tx_hash>`, and the middleware validates the transfer on-chain and returns the payload instantly.

---

## ⚡ Quickstart Client Snippets

### Python (Securing an OpenAI / Anthropic Call)
```python
import requests

SHIELD_URL = "http://localhost:3000"
HEADERS = {"X-RapidAPI-Proxy-Secret": "YOUR_SECRET"}  # or X-Payment-Tx

# 1. Mask prompt before sending to LLM
prompt = "Send report for user alice@acme.com with key sk-12345678901234567890."
mask_res = requests.post(f"{SHIELD_URL}/v1/mask", json={"text": prompt}, headers=HEADERS).json()

safe_text = mask_res["masked_text"]
token = mask_res["recovery_token"]
# safe_text is: "Send report for user {{SURROGATE_EMAIL_1}} with key {{SURROGATE_SECRET_KEY_1}}."

# 2. Call OpenAI with sanitized prompt (OpenAI never sees your PII)
# llm_response = openai.ChatCompletion.create(messages=[{"role": "user", "content": safe_text}])
llm_output = "Processed request for {{SURROGATE_EMAIL_1}} successfully."

# 3. Unmask completion to restore original entities
unmask_res = requests.post(f"{SHIELD_URL}/v1/unmask", json={"text": llm_output, "recovery_token": token}, headers=HEADERS).json()
print(unmask_res["unmasked_text"])
# Output: "Processed request for alice@acme.com successfully."
```

### JavaScript / Node.js
```javascript
const res = await fetch("https://your-api.railway.app/v1/mask", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-RapidAPI-Proxy-Secret": process.env.RAPIDAPI_PROXY_SECRET,
  },
  body: JSON.stringify({
    text: "Transfer 50 USDC to 0x1111111111111111111111111111111111111111.",
  }),
});
const data = await res.json();
console.log(data.masked_text);
// "Transfer 50 USDC to {{SURROGATE_ETH_ADDRESS_1}}."
```

---

## 📦 1-Click Deployment

### Deploy to Railway / Render / Fly.io:
1. Connect this repo to Railway or Render.
2. It detects the `Dockerfile` automatically.
3. Set environment variables:
   - `BASE_PAYEE_ADDRESS=0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7`
   - `RAPIDAPI_PROXY_SECRET=<generate_random_secret>`
4. Click **Deploy**.

---

## 🌐 Publish to RapidAPI Hub (3 Steps)
1. Go to [RapidAPI Studio](https://rapidapi.com/studio).
2. Click **Create New API** -> **Import from OpenAPI Spec**.
3. Upload [`openapi.json`](./openapi.json), set your upstream URL (e.g. `https://your-app.railway.app`), configure your pricing tiers ($0 free tier with 50 calls, $19 Pro tier with 2,500 calls), and hit **Publish**!
