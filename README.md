# AI Shield Gateway API

[![CI](https://github.com/Simultech369/ai-shield-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/Simultech369/ai-shield-gateway/actions/workflows/ci.yml)
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/new?template=https%3A%2F%2Fgithub.com%2FSimultech369%2Fai-shield-gateway)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Simultech369/ai-shield-gateway)

**Zero-Leak PII Surrogate Shield, Drop-In OpenAI Privacy Proxy, AI Agent Web Extractor & Cryptographic Grounding Verifier with Dual-Rail Monetization (RapidAPI + x402 on Base).**

---

## 🚀 Overview

The **AI Shield Gateway** is an automated privacy, security, and verification infrastructure service designed for LLM applications, RAG pipelines, and autonomous AI agents:

1. **Drop-In OpenAI Privacy Proxy (`POST /v1/chat/completions` & `POST /v1/proxy`):**
   - Seamless drop-in replacement for OpenAI endpoints. Set `base_url="https://ai-shield-gateway.up.railway.app/v1"`.
   - Intercepts requests, bijectively masks emails, API keys, private keys, ETH/crypto addresses, IP addresses, and filesystem paths before egress to OpenAI/Groq/Anthropic.
   - Forwards sanitized payload to upstream model provider (OpenAI never sees your raw PII or secrets).
   - Re-hydrates completions on ingress and attaches cryptographic SHA-256 evidence receipts.

2. **Web-to-Markdown AI Agent Extractor (`POST /v1/extract`):**
   - High-speed web scraper specifically formatted for AI agents and LLMs.
   - Strips boilerplate, navigation, ads, footers, and scripts.
   - Emits clean, token-efficient semantic Markdown with headings, code blocks, links, tables, and structured metadata.
   - Built-in SSRF protection blocking private IP ranges and internal network attacks.

3. **Reversible PII Shield (`POST /v1/mask` & `POST /v1/unmask`):**
   - Bijective surrogate masking (`{{SURROGATE_EMAIL_1}}`, etc.) with co-reference preservation.
   - Generates AES-256 encrypted recovery tokens for offline or custom pipeline unmasking.

4. **Cryptographic Citation Grounding Verifier (`POST /v1/verify-citations`):**
   - Verifies whether LLM citations exist verbatim in source corpus documents.
   - Catches phantom hallucinations and emits tamper-evident SHA-256 evidence receipts.

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

## ⚡ 1-Line Drop-In OpenAI SDK Usage

### Python (Drop-In OpenAI Client)
```python
from openai import OpenAI
import os

# Point official OpenAI client to AI Shield Gateway
client = OpenAI(
    base_url="https://ai-shield-gateway.up.railway.app/v1",
    api_key=os.environ["OPENAI_API_KEY"],
    default_headers={
        "X-RapidAPI-Proxy-Secret": os.environ["RAPIDAPI_PROXY_SECRET"],
    },
)

# Call completions as normal - all PII is automatically masked on egress and unmasked on return!
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[
        {"role": "system", "content": "You are a customer assistant."},
        {"role": "user", "content": "Send refund for alice@acme.org to 0x1111111111111111111111111111111111111111."}
    ],
)

print(response.choices[0].message.content)
```

### Python (Web-to-Markdown AI Agent Scraper)
```python
import requests

res = requests.post(
    "https://ai-shield-gateway.up.railway.app/v1/extract",
    json={"url": "https://news.ycombinator.com"},
    headers={"X-RapidAPI-Proxy-Secret": "YOUR_SECRET"},
).json()

print(res["title"])
print(res["markdown"]) # Clean markdown, boilerplate stripped, agent-ready!
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
3. Upload [`openapi.json`](./openapi.json), set your upstream URL (e.g. `https://ai-shield-gateway.up.railway.app`), configure your pricing tiers ($0 free tier with 50 calls, $19 Pro tier with 2,500 calls), and hit **Publish**!
