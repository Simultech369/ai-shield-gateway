import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import { PiiSafeInferenceProxy, verifyPiiInferenceProxyReceipt } from "./engine/pii_safe_inference_proxy.mjs";
import { CitationGroundingVerifier } from "./engine/citation_grounding_verifier.mjs";
import { extractUrlToMarkdown } from "./engine/web_extractor.mjs";
import { scanSolidityCode } from "./engine/solidity_scanner.mjs";
import { createPaywallMiddleware } from "./middleware/paywall.mjs";

const app = express();
const PORT = process.env.PORT || 3000;
const piiProxy = new PiiSafeInferenceProxy();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// In-memory or encrypted token store for recovery tokens
const SECRET_SALT = process.env.SESSION_SECRET || "simultech_pii_shield_secret_key_32b!";

function encryptSessionMap(tokenMap) {
  const payload = JSON.stringify(Array.from(tokenMap.entries()));
  const cipher = crypto.createCipheriv("aes-256-cbc", crypto.createHash("sha256").update(SECRET_SALT).digest(), Buffer.alloc(16, 0));
  let encrypted = cipher.update(payload, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

function decryptSessionMap(encryptedHex) {
  try {
    const decipher = crypto.createDecipheriv("aes-256-cbc", crypto.createHash("sha256").update(SECRET_SALT).digest(), Buffer.alloc(16, 0));
    let decrypted = decipher.update(encryptedHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return new Map(JSON.parse(decrypted));
  } catch {
    return null;
  }
}

// 1. Health Probe
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ai-shield-gateway",
    version: "1.1.0",
    uptime_seconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// 2. Root Overview
app.get("/", (req, res) => {
  res.json({
    name: "AI Shield Gateway API",
    tagline: "Zero-Leak PII Surrogate Shield, Web Extractor & Cryptographic Grounding Verifier",
    version: "1.1.0",
    monetization: {
      rapidapi: "https://rapidapi.com/simultech/api/ai-shield-gateway",
      x402_base: {
        payee: process.env.BASE_PAYEE_ADDRESS || "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7",
        price_usdc: "0.05",
        chain: "Base (8453)",
      },
    },
    endpoints: {
      "POST /v1/chat/completions": "Drop-in OpenAI proxy. Egress PII masking, upstream forward, ingress re-hydration with cryptographic receipt",
      "POST /v1/proxy": "Alias for /v1/chat/completions with flexible provider options (OpenAI, Groq, Ollama)",
      "POST /v1/mask": "Mask sensitive PII/secrets with reversible surrogates before LLM egress",
      "POST /v1/unmask": "Re-hydrate original entities in LLM completions via recovery token",
      "POST /v1/extract": "Clean semantic Web-to-Markdown scraper for AI agents with SSRF protection",
      "POST /v1/verify-citations": "Verify RAG & LLM quote citations against ground-truth source text",
    },
  });
});

// Attach Paywall Middleware
app.use(createPaywallMiddleware());

// 3. POST /v1/mask - Sanitize text or chat messages
app.post("/v1/mask", (req, res) => {
  const { text, messages } = req.body;

  if (!text && !messages) {
    return res.status(400).json({
      error: "Missing required parameter: provide either 'text' (string) or 'messages' (array).",
    });
  }

  const { maskedInput, session } = piiProxy.maskPrompt(text || messages);
  const recoveryToken = encryptSessionMap(session.tokenToOriginal);

  const receipt = piiProxy.generateReceipt({
    session,
    maskedInput,
    unmaskedResponse: "(pending_completion)",
  });

  if (typeof text === "string") {
    return res.json({
      success: true,
      masked_text: maskedInput,
      recovery_token: recoveryToken,
      entities_masked: session.totalEntitiesMasked,
      breakdown: session.categoryCounts,
      receipt,
    });
  }

  return res.json({
    success: true,
    masked_messages: maskedInput,
    recovery_token: recoveryToken,
    entities_masked: session.totalEntitiesMasked,
    breakdown: session.categoryCounts,
    receipt,
  });
});

// 4. POST /v1/unmask - Restore original PII into completion
app.post("/v1/unmask", (req, res) => {
  const { text, recovery_token } = req.body;

  if (!text || typeof text !== "string") {
    return res.status(400).json({ error: "Missing required 'text' string to unmask." });
  }

  if (!recovery_token || typeof recovery_token !== "string") {
    return res.status(400).json({ error: "Missing required 'recovery_token'." });
  }

  const tokenToOriginal = decryptSessionMap(recovery_token);
  if (!tokenToOriginal) {
    return res.status(400).json({ error: "Invalid or corrupted recovery_token." });
  }

  let unmasked = text;
  let restoredCount = 0;
  for (const [token, original] of tokenToOriginal.entries()) {
    if (unmasked.includes(token)) {
      unmasked = unmasked.split(token).join(original);
      restoredCount++;
    }
  }

  return res.json({
    success: true,
    unmasked_text: unmasked,
    entities_restored: restoredCount,
  });
});

// 5. POST /v1/chat/completions & POST /v1/proxy - Drop-in LLM Privacy Proxy
async function handleChatProxy(req, res) {
  const { messages, prompt, model, provider, provider_url, mock_completion, temperature, max_tokens } = req.body;

  if (!messages && !prompt) {
    return res.status(400).json({
      error: "Missing required parameter: provide 'messages' array or 'prompt' string.",
    });
  }

  // 1. Mask outbound input
  const inputToMask = messages || prompt;
  const { maskedInput, session } = piiProxy.maskPrompt(inputToMask);

  let rawUpstreamCompletion = "";
  let upstreamModel = model || "gpt-4o";

  // 2. Handle Mock / Test Mode
  if (mock_completion) {
    rawUpstreamCompletion = typeof mock_completion === "object"
      ? (mock_completion.content || JSON.stringify(mock_completion))
      : String(mock_completion);
  } else if (process.env.NODE_ENV === "test" && !process.env.OPENAI_API_KEY) {
    // Hermetic fallback during unit tests
    rawUpstreamCompletion = `Acknowledged. Received masked payload with ${session.totalEntitiesMasked} surrogates.`;
  } else {
    // 3. Dispatch to Upstream Provider
    const targetUrl = provider_url || (
      provider === "groq"
        ? "https://api.groq.com/openai/v1/chat/completions"
        : "https://api.openai.com/v1/chat/completions"
    );

    const downstreamKey = req.headers["x-downstream-api-key"] ||
      (req.headers.authorization && !req.headers.authorization.includes("test_admin")
        ? req.headers.authorization.replace(/^Bearer\s+/i, "")
        : process.env.OPENAI_API_KEY);

    if (!downstreamKey) {
      return res.status(401).json({
        error: "Missing downstream LLM API key. Pass 'X-Downstream-Api-Key: <key>' or 'Authorization: Bearer <key>'.",
      });
    }

    try {
      const upstreamPayload = {
        model: upstreamModel,
        messages: Array.isArray(maskedInput) ? maskedInput : [{ role: "user", content: maskedInput }],
        ...(temperature !== undefined ? { temperature } : {}),
        ...(max_tokens !== undefined ? { max_tokens } : {}),
      };

      const upstreamRes = await fetch(targetUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${downstreamKey}`,
        },
        body: JSON.stringify(upstreamPayload),
      });

      if (!upstreamRes.ok) {
        const errorText = await upstreamRes.text();
        return res.status(upstreamRes.status).json({
          error: "Upstream LLM Provider Error",
          upstream_status: upstreamRes.status,
          upstream_body: errorText,
        });
      }

      const upstreamData = await upstreamRes.json();
      rawUpstreamCompletion = upstreamData.choices?.[0]?.message?.content || "";
    } catch (err) {
      return res.status(502).json({
        error: `Upstream gateway error: ${err.message}`,
      });
    }
  }

  // 4. Ingress Re-hydration
  const unmaskedCompletion = piiProxy.unmaskResponse(rawUpstreamCompletion, session);

  // 5. Sealed Receipt Generation
  const receipt = piiProxy.generateReceipt({
    session,
    maskedInput,
    unmaskedResponse: unmaskedCompletion,
    provider: provider || "openai",
  });

  res.setHeader("X-PII-Shield-Entities-Masked", session.totalEntitiesMasked);
  res.setHeader("X-PII-Shield-Receipt-Hash", receipt.evidence_sha256);

  // Format standard OpenAI chat completion response
  return res.json({
    id: `chatcmpl-pii-${crypto.randomUUID().slice(0, 8)}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: upstreamModel,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: unmaskedCompletion,
        },
        finish_reason: "stop",
      },
    ],
    usage: {
      prompt_tokens: Math.ceil(JSON.stringify(maskedInput).length / 4),
      completion_tokens: Math.ceil(unmaskedCompletion.length / 4),
      total_tokens: Math.ceil((JSON.stringify(maskedInput).length + unmaskedCompletion.length) / 4),
    },
    pii_shield: {
      entities_masked: session.totalEntitiesMasked,
      breakdown: session.categoryCounts,
      receipt,
    },
  });
}

app.post("/v1/chat/completions", handleChatProxy);
app.post("/v1/proxy", handleChatProxy);

// 6. POST /v1/extract - AI Agent Web-to-Markdown Scraper
app.post("/v1/extract", async (req, res) => {
  const { url, options } = req.body;

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing required 'url' parameter string." });
  }

  try {
    const result = await extractUrlToMarkdown(url, options || {});
    return res.json({
      success: true,
      ...result,
    });
  } catch (err) {
    const isSsrf = err.message.includes("SSRF Blocked");
    return res.status(isSsrf ? 403 : 502).json({
      success: false,
      error: err.message,
    });
  }
});

// 7. POST /v1/verify-citations - RAG Citation Grounding Verifier
app.post("/v1/verify-citations", (req, res) => {
  const { claim_id, citations, context_packets, options } = req.body;

  if (!citations && !options?.unverifiedExplanation) {
    return res.status(400).json({ error: "Missing required 'citations' array." });
  }

  const verifier = new CitationGroundingVerifier();
  const result = verifier.verifyCitations(claim_id, citations || [], context_packets || {}, options || {});

  return res.json({
    success: true,
    result,
  });
});

// 8. POST /v1/scan-contract - Solidity Invariant & Security Linter
app.post("/v1/scan-contract", (req, res) => {
  const { code, options } = req.body;

  if (!code || typeof code !== "string") {
    return res.status(400).json({ error: "Missing required 'code' parameter string containing Solidity code." });
  }

  try {
    const result = scanSolidityCode(code, options || {});
    return res.json(result);
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

// Start Server
if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("src/server.mjs")) {
  app.listen(PORT, () => {
    console.log(`[AI-Shield-Gateway] Listening on port ${PORT}`);
    console.log(`[AI-Shield-Gateway] RapidAPI: enabled | x402 Base USDC: ${process.env.BASE_PAYEE_ADDRESS || "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7"}`);
  });
}

export default app;
