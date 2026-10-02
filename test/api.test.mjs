import assert from "node:assert/strict";
import http from "node:http";
import app from "../src/server.mjs";

process.env.NODE_ENV = "test";
process.env.RAPIDAPI_PROXY_SECRET = "test_rapidapi_secret_123";
process.env.BASE_PAYEE_ADDRESS = "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7";

let server;
let baseUrl;

async function request(method, path, body = null, headers = {}) {
  const url = `${baseUrl}${path}`;
  const res = await fetch(url, {
    method,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
    body: body ? JSON.stringify(body) : null,
  });

  const status = res.status;
  const resHeaders = Object.fromEntries(res.headers.entries());
  let data = null;
  try {
    data = await res.json();
  } catch {}

  return { status, headers: resHeaders, data };
}

async function runTests() {
  console.log("=== Running AI Shield Gateway API Tests ===");

  server = app.listen(0);
  const port = server.address().port;
  baseUrl = `http://localhost:${port}`;

  try {
    // 1. Health Probe
    {
      const res = await request("GET", "/health");
      assert.equal(res.status, 200);
      assert.equal(res.data.status, "ok");
      assert.equal(res.data.service, "ai-shield-gateway");
      console.log("✔ GET /health returns 200 OK");
    }

    // 2. Unauthenticated request triggers HTTP 402 Payment Required
    {
      const res = await request("POST", "/v1/mask", {
        text: "My email is alice@example.com",
      });
      assert.equal(res.status, 402);
      assert.equal(res.data.status, 402);
      assert.equal(res.data.error, "Payment Required");
      assert.equal(res.headers["x-accept-currency"], "USDC");
      assert.equal(res.headers["x-pay-to"], "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7");
      assert.equal(res.data.x402.network, "base");
      console.log("✔ Unauthenticated request returns HTTP 402 Payment Required with x402 headers");
    }

    // 3. RapidAPI authenticated request masks sensitive data and generates receipt
    let recoveryToken;
    let maskedText;
    {
      const res = await request(
        "POST",
        "/v1/mask",
        {
          text: "Send $100 to 0x1111111111111111111111111111111111111111 and notify bob@acme.org with key sk-abcdef1234567890123456.",
        },
        {
          "x-rapidapi-proxy-secret": "test_rapidapi_secret_123",
          "x-rapidapi-user": "test_user_42",
        }
      );

      assert.equal(res.status, 200);
      assert.equal(res.data.success, true);
      assert(res.data.masked_text.includes("{{SURROGATE_ETH_ADDRESS_1}}"));
      assert(res.data.masked_text.includes("{{SURROGATE_EMAIL_1}}"));
      assert(res.data.masked_text.includes("{{SURROGATE_SECRET_KEY_1}}"));
      assert.equal(res.data.entities_masked, 3);
      assert(res.data.recovery_token);
      assert(res.data.receipt);
      assert(res.data.receipt.evidence_sha256);

      recoveryToken = res.data.recovery_token;
      maskedText = res.data.masked_text;
      console.log("✔ POST /v1/mask correctly masks PII and emits receipt");
    }

    // 4. Unmask restores original entities seamlessly
    {
      const llmCompletion = `Processed transfer for {{SURROGATE_ETH_ADDRESS_1}}. Receipt sent to {{SURROGATE_EMAIL_1}}.`;
      const res = await request(
        "POST",
        "/v1/unmask",
        {
          text: llmCompletion,
          recovery_token: recoveryToken,
        },
        {
          "x-rapidapi-proxy-secret": "test_rapidapi_secret_123",
        }
      );

      assert.equal(res.status, 200);
      assert.equal(res.data.success, true);
      assert(res.data.unmasked_text.includes("0x1111111111111111111111111111111111111111"));
      assert(res.data.unmasked_text.includes("bob@acme.org"));
      assert.equal(res.data.entities_restored, 2);
      console.log("✔ POST /v1/unmask correctly restores original PII values");
    }

    // 5. x402 on-chain payment rail test
    {
      const res = await request(
        "POST",
        "/v1/mask",
        {
          text: "Secret server at 192.168.1.50 with path C:\\Users\\Alice\\keys.txt",
        },
        {
          "x-payment-tx": "0xtest_valid_sample_hash_9876",
        }
      );

      assert.equal(res.status, 200);
      assert.equal(res.data.success, true);
      assert(res.data.masked_text.includes("{{SURROGATE_IP_ADDRESS_1}}"));
      console.log("✔ POST /v1/mask succeeds via x402 Base payment validation");
    }

    // 6. Verify Citations Grounding Verifier
    {
      const contextPackets = {
        "report.txt": "The quarterly gross revenue was $4.2M representing a 15% increase year-over-year.",
      };
      const citations = [
        {
          file: "report.txt",
          quote: "The quarterly gross revenue was $4.2M representing a 15% increase year-over-year.",
          lines: [1, 1],
        },
      ];

      const res = await request(
        "POST",
        "/v1/verify-citations",
        {
          claim_id: "claim_test_101",
          citations,
          context_packets: contextPackets,
        },
        {
          "x-rapidapi-proxy-secret": "test_rapidapi_secret_123",
        }
      );

      assert.equal(res.status, 200);
      assert.equal(res.data.success, true);
      assert.equal(res.data.result.exact_matches, 1);
      assert.equal(res.data.result.provenance_badge, "[PASSAGE_GROUNDED]");
      console.log("✔ POST /v1/verify-citations returns verified grounding receipt");
    }

    // 7. POST /v1/chat/completions (OpenAI Drop-In Privacy Proxy)
    {
      const res = await request(
        "POST",
        "/v1/chat/completions",
        {
          model: "gpt-4o",
          messages: [
            { role: "system", content: "You are a helpful assistant." },
            { role: "user", content: "My email is alice@cybercorp.com and my server is 10.0.0.4. What should I configure?" },
          ],
          mock_completion: "Your server {{SURROGATE_IP_ADDRESS_1}} is configured. Notification sent to {{SURROGATE_EMAIL_1}}.",
        },
        {
          "x-rapidapi-proxy-secret": "test_rapidapi_secret_123",
        }
      );

      assert.equal(res.status, 200);
      assert.equal(res.data.object, "chat.completion");
      assert(res.data.choices && res.data.choices.length > 0);
      const content = res.data.choices[0].message.content;

      // Assert complete re-hydration of original values into the assistant response
      assert(content.includes("10.0.0.4"), `Expected 10.0.0.4 in content, got: ${content}`);
      assert(content.includes("alice@cybercorp.com"), `Expected alice@cybercorp.com in content, got: ${content}`);
      assert(!content.includes("{{SURROGATE_"), "Surrogate tokens must not leak in final unmasked response");

      // Assert cryptographic receipt & headers
      assert.equal(res.data.pii_shield.entities_masked, 2);
      assert(res.data.pii_shield.receipt.evidence_sha256);
      assert.equal(res.headers["x-pii-shield-entities-masked"], "2");
      console.log("✔ POST /v1/chat/completions masks on egress and re-hydrates on ingress with sealed receipt");
    }

    // 8. POST /v1/proxy (Alias endpoint)
    {
      const res = await request(
        "POST",
        "/v1/proxy",
        {
          prompt: "Verify transfer to 0x2222222222222222222222222222222222222222",
          mock_completion: "Transfer confirmed to {{SURROGATE_ETH_ADDRESS_1}}.",
        },
        {
          "x-payment-tx": "0xtest_valid_sample_hash_9877",
        }
      );

      assert.equal(res.status, 200);
      assert(res.data.choices[0].message.content.includes("0x2222222222222222222222222222222222222222"));
      console.log("✔ POST /v1/proxy functions seamlessly as an alias over x402 Base payment rail");
    }

    // 9. POST /v1/extract (SSRF protection test)
    {
      const res = await request(
        "POST",
        "/v1/extract",
        {
          url: "http://127.0.0.1:8080/internal-metrics",
        },
        {
          "x-rapidapi-proxy-secret": "test_rapidapi_secret_123",
        }
      );

      assert.equal(res.status, 403);
      assert.equal(res.data.success, false);
      assert(res.data.error.includes("SSRF Blocked"));
      console.log("✔ POST /v1/extract enforces strict SSRF blocking on private IP ranges");
    }

    console.log("\nALL 9/9 API TEST SUITES PASSED CLEANLY!");
  } finally {
    server.close();
  }
}

runTests().catch((err) => {
  console.error("Test execution failed:", err);
  if (server) server.close();
  process.exit(1);
});
