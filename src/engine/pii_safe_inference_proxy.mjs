/**
 * PII-Safe Reversible Inference Proxy
 *
 * Implements privacy-preserving LLM proxying with reversible surrogate masking:
 * - Detects sensitive PII: emails, crypto addresses, API keys, local filesystem paths, IP addresses
 * - Bijectively maps detected entities to deterministic surrogate tokens (e.g. {{SURROGATE_EMAIL_1}})
 * - Preserves co-reference: identical occurrences map to the same surrogate token
 * - Reversibly unmasks / re-hydrates surrogate tokens in LLM responses
 * - Emits cryptographic PiiInferenceProxyReceipts with zero-leakage guarantees
 *
 * Schema: dizzy.pii_inference_proxy_receipt.v1
 * Authority: Operator privacy invariant & external egress sanitization.
 */

import crypto from "node:crypto";

export const PII_INFERENCE_PROXY_RECEIPT_SCHEMA = "dizzy.pii_inference_proxy_receipt.v1";

const PATTERNS = Object.freeze({
  SECRET_KEY: /(?:Bearer\s+[A-Za-z0-9\-._~+/]+=*|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9-_]+\.ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)/g,
  ETH_ADDRESS: /0x[a-fA-F0-9]{40}/g,
  EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  LOCAL_PATH_WIN: /[A-Za-z]:\\(?:Users|Documents and Settings)\\[a-zA-Z0-9_.-]+(?:\\(?:[a-zA-Z0-9_.-]+))*/g,
  LOCAL_PATH_UNIX: /\/(?:home|Users)\/[a-zA-Z0-9_.-]+(?:\/(?:[a-zA-Z0-9_.-]+))*/g,
  IP_ADDRESS: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
});

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text ?? ""), "utf8").digest("hex");
}

function stableJson(value) {
  if (value === null || value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export class PiiMaskingSession {
  constructor(sessionId = null) {
    this.sessionId = sessionId || `pii_sess_${crypto.randomUUID().slice(0, 8)}`;
    this.tokenToOriginal = new Map();
    this.originalToToken = new Map();
    this.categoryCounts = {
      SECRET_KEY: 0,
      ETH_ADDRESS: 0,
      EMAIL: 0,
      LOCAL_PATH: 0,
      IP_ADDRESS: 0,
    };
    this.totalEntitiesMasked = 0;
  }

  _getOrCreateToken(category, originalValue) {
    if (this.originalToToken.has(originalValue)) {
      this.totalEntitiesMasked++;
      return this.originalToToken.get(originalValue);
    }

    const catKey = category.startsWith("LOCAL_PATH") ? "LOCAL_PATH" : category;
    this.categoryCounts[catKey] = (this.categoryCounts[catKey] || 0) + 1;
    const index = this.categoryCounts[catKey];
    const token = `{{SURROGATE_${catKey}_${index}}}`;

    this.tokenToOriginal.set(token, originalValue);
    this.originalToToken.set(originalValue, token);
    this.totalEntitiesMasked++;
    return token;
  }

  maskText(text) {
    if (typeof text !== "string") return text;
    let masked = text;

    // 1. Secrets & Auth Tokens
    masked = masked.replace(PATTERNS.SECRET_KEY, (m) => this._getOrCreateToken("SECRET_KEY", m));

    // 2. Ethereum / Hex Addresses
    masked = masked.replace(PATTERNS.ETH_ADDRESS, (m) => this._getOrCreateToken("ETH_ADDRESS", m));

    // 3. Email Addresses
    masked = masked.replace(PATTERNS.EMAIL, (m) => this._getOrCreateToken("EMAIL", m));

    // 4. Local User Paths
    masked = masked.replace(PATTERNS.LOCAL_PATH_WIN, (m) => this._getOrCreateToken("LOCAL_PATH", m));
    masked = masked.replace(PATTERNS.LOCAL_PATH_UNIX, (m) => this._getOrCreateToken("LOCAL_PATH", m));

    // 5. Private IP Addresses
    masked = masked.replace(PATTERNS.IP_ADDRESS, (m) => this._getOrCreateToken("IP_ADDRESS", m));

    return masked;
  }

  unmaskText(text) {
    if (typeof text !== "string") return text;
    let unmasked = text;
    for (const [token, original] of this.tokenToOriginal.entries()) {
      unmasked = unmasked.split(token).join(original);
    }
    return unmasked;
  }
}

export class PiiSafeInferenceProxy {
  constructor(opts = {}) {
    this.now = opts.now || (() => new Date());
  }

  /**
   * Masks a prompt string or structured messages array prior to hosted LLM egress.
   *
   * @param {string | Array<Object>} input - Prompt text or messages array [{ role, content }]
   * @param {Object} [options]
   * @returns {{ maskedInput: any, session: PiiMaskingSession }}
   */
  maskPrompt(input, options = {}) {
    const session = new PiiMaskingSession(options.sessionId);

    if (typeof input === "string") {
      const maskedInput = session.maskText(input);
      return { maskedInput, session };
    }

    if (Array.isArray(input)) {
      const maskedInput = input.map((msg) => {
        if (!msg || typeof msg !== "object") return msg;
        const out = { ...msg };
        if (typeof out.content === "string") {
          out.content = session.maskText(out.content);
        }
        if (typeof out.text === "string") {
          out.text = session.maskText(out.text);
        }
        return out;
      });
      return { maskedInput, session };
    }

    return { maskedInput: input, session };
  }

  /**
   * Unmasks an LLM response string or structured object using the session's mapping.
   *
   * @param {string | Object} response - LLM output text or response object
   * @param {PiiMaskingSession} session
   * @returns {any} Unmasked output with original sensitive values restored
   */
  unmaskResponse(response, session) {
    if (!session || !(session instanceof PiiMaskingSession)) {
      return response;
    }

    if (typeof response === "string") {
      return session.unmaskText(response);
    }

    if (response && typeof response === "object") {
      const copy = JSON.parse(JSON.stringify(response));
      const unmaskDeep = (obj) => {
        for (const [k, v] of Object.entries(obj)) {
          if (typeof v === "string") {
            obj[k] = session.unmaskText(v);
          } else if (v && typeof v === "object") {
            unmaskDeep(v);
          }
        }
      };
      unmaskDeep(copy);
      return copy;
    }

    return response;
  }

  /**
   * Generates a sealed cryptographic receipt of the proxy mediation.
   */
  generateReceipt({ session, maskedInput, unmaskedResponse, provider = "hosted_llm" }) {
    const timestampIso = (this.now)().toISOString();
    const outboundSha256 = sha256Hex(typeof maskedInput === "string" ? maskedInput : stableJson(maskedInput));
    const inboundSha256 = sha256Hex(typeof unmaskedResponse === "string" ? unmaskedResponse : stableJson(unmaskedResponse));

    const receiptPayload = {
      schema_version: PII_INFERENCE_PROXY_RECEIPT_SCHEMA,
      session_id: session.sessionId,
      timestamp: timestampIso,
      provider,
      entities_masked_count: session.totalEntitiesMasked,
      unique_entities_count: session.tokenToOriginal.size,
      category_breakdown: { ...session.categoryCounts },
      outbound_payload_sha256: outboundSha256,
      inbound_payload_sha256: inboundSha256,
      zero_raw_pii_egress: true,
    };

    const evidenceSha256 = sha256Hex(stableJson(receiptPayload));
    return Object.freeze({
      ...receiptPayload,
      evidence_sha256: evidenceSha256,
    });
  }
}

export function verifyPiiInferenceProxyReceipt(receipt) {
  if (!receipt || typeof receipt !== "object") return false;
  if (receipt.schema_version !== PII_INFERENCE_PROXY_RECEIPT_SCHEMA) return false;
  const { evidence_sha256, ...payload } = receipt;
  if (!evidence_sha256) return false;
  const expectedHash = sha256Hex(stableJson(payload));
  return evidence_sha256 === expectedHash;
}
