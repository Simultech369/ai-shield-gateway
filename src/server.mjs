import express from "express";
import cors from "cors";
import crypto from "node:crypto";
import { PiiSafeInferenceProxy, verifyPiiInferenceProxyReceipt } from "./engine/pii_safe_inference_proxy.mjs";
import { CitationGroundingVerifier } from "./engine/citation_grounding_verifier.mjs";
import { createPaywallMiddleware } from "./middleware/paywall.mjs";

const app = express();
const PORT = process.env.PORT || 3000;
const piiProxy = new PiiSafeInferenceProxy();

app.use(cors());
app.use(express.json({ limit: "10mb" }));

// In-memory or encrypted token store for recovery tokens
const sessionStore = new Map();

// Helper to encrypt session recovery state
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
  } catch (err) {
    return null;
  }
}

// 1. Health Probe
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "ai-shield-gateway",
    version: "1.0.0",
    uptime_seconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// 2. Root Overview
app.get("/", (req, res) => {
  res.json({
    name: "AI Shield Gateway API",
    tagline: "Zero-Leak PII Surrogate Shield & Cryptographic Grounding Verifier",
    monetization: {
      rapidapi: "https://rapidapi.com/simultech/api/ai-shield-gateway",
      x402_base: {
        payee: process.env.BASE_PAYEE_ADDRESS || "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7",
        price_usdc: "0.05",
        chain: "Base (8453)",
      },
    },
    endpoints: {
      "POST /v1/mask": "Mask sensitive PII/secrets with reversible surrogates before LLM egress",
      "POST /v1/unmask": "Re-hydrate original entities in LLM completions via recovery token",
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

// 5. POST /v1/verify-citations - RAG Citation Grounding Verifier
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

// Start Server
if (process.argv[1] && process.argv[1].replace(/\\/g, "/").endsWith("src/server.mjs")) {
  app.listen(PORT, () => {
    console.log(`[AI-Shield-Gateway] Listening on port ${PORT}`);
    console.log(`[AI-Shield-Gateway] RapidAPI: enabled | x402 Base USDC: ${process.env.BASE_PAYEE_ADDRESS || "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7"}`);
  });
}

export default app;
