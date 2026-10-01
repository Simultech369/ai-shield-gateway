import crypto from "node:crypto";

const DEFAULT_PAYEE = "0xEa3A353Fb3fc88DB8F0FA1E6Ea541FEdc9F5F0E7";
const BASE_USDC_CONTRACT = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const DEFAULT_PRICE_USDC = "0.05";
const DEFAULT_BASE_RPC = process.env.BASE_RPC_URL || "https://mainnet.base.org";

// Track settled transactions to prevent double-spending
const processedTransactions = new Set();

/**
 * Validates on-chain ERC20 USDC transfer or native transfer on Base via RPC.
 */
async function verifyBaseTransaction(txHash, payeeAddress, minAmountUsdc) {
  if (!txHash || typeof txHash !== "string" || !txHash.startsWith("0x")) {
    return { valid: false, reason: "Invalid transaction hash format" };
  }

  if (processedTransactions.has(txHash.toLowerCase())) {
    return { valid: false, reason: "Transaction hash already consumed (replay prevented)" };
  }

  // Development / test bypass mode
  if (process.env.NODE_ENV === "test" && txHash.startsWith("0xtest_valid_")) {
    processedTransactions.add(txHash.toLowerCase());
    return { valid: true, txHash, amountUsdc: minAmountUsdc };
  }

  try {
    const res = await fetch(DEFAULT_BASE_RPC, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getTransactionReceipt",
        params: [txHash],
      }),
    });

    if (!res.ok) {
      return { valid: false, reason: `RPC request failed with HTTP ${res.status}` };
    }

    const data = await res.json();
    const receipt = data.result;

    if (!receipt) {
      return { valid: false, reason: "Transaction receipt not found or still pending" };
    }

    if (receipt.status !== "0x1") {
      return { valid: false, reason: "Transaction reverted on-chain" };
    }

    // Verify logs for ERC-20 Transfer to payeeAddress
    // Transfer(address,address,uint256) topic: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
    const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
    const normalizedPayee = payeeAddress.toLowerCase().replace("0x", "").padStart(64, "0");

    let transferFound = false;
    for (const log of receipt.logs || []) {
      const isUsdc = log.address?.toLowerCase() === BASE_USDC_CONTRACT.toLowerCase();
      const isTransfer = log.topics?.[0]?.toLowerCase() === transferTopic;
      const isRecipient = log.topics?.[2]?.toLowerCase() === `0x${normalizedPayee}`;

      if (isUsdc && isTransfer && isRecipient) {
        // Base USDC has 6 decimals
        const rawValue = BigInt(log.data);
        const minRaw = BigInt(Math.floor(parseFloat(minAmountUsdc) * 1_000_000));
        if (rawValue >= minRaw) {
          transferFound = true;
          break;
        }
      }
    }

    if (!transferFound) {
      return { valid: false, reason: "No qualifying USDC transfer to payee address found in transaction logs" };
    }

    processedTransactions.add(txHash.toLowerCase());
    return { valid: true, txHash, blockNumber: receipt.blockNumber };
  } catch (err) {
    return { valid: false, reason: `RPC error: ${err.message}` };
  }
}

/**
 * Dual-Rail Paywall Middleware:
 * 1. RapidAPI Proxy Secret (Web2 developer channel)
 * 2. Admin Bearer Token (Direct client / enterprise channel)
 * 3. x402 HTTP 402 Protocol on Base (Autonomous AI agent channel)
 */
export function createPaywallMiddleware(options = {}) {
  return async function paywall(req, res, next) {
    const payee = options.payee || process.env.BASE_PAYEE_ADDRESS || DEFAULT_PAYEE;
    const priceUsdc = options.priceUsdc || process.env.PRICE_USDC || DEFAULT_PRICE_USDC;
    const rapidApiSecret = options.rapidApiSecret || process.env.RAPIDAPI_PROXY_SECRET;
    const adminApiKey = options.adminApiKey || process.env.ADMIN_API_KEY;

    // 1. Allow health and documentation endpoints freely
    if (req.path === "/health" || req.path === "/openapi.json" || req.path === "/") {
      return next();
    }

    // 2. Check RapidAPI Gateway
    const clientRapidSecret = req.headers["x-rapidapi-proxy-secret"];
    if (rapidApiSecret && clientRapidSecret === rapidApiSecret) {
      req.authContext = {
        method: "rapidapi",
        user: req.headers["x-rapidapi-user"] || "rapidapi_consumer",
        subscription: req.headers["x-rapidapi-subscription"] || "active",
      };
      return next();
    }

    // 3. Check Direct Bearer API Key
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.slice(7).trim();
      if (adminApiKey && token === adminApiKey) {
        req.authContext = { method: "admin_token", user: "admin" };
        return next();
      }
    }

    // 4. Check x402 On-Chain Micropayment Header
    const paymentTx = req.headers["x-payment-tx"] || req.headers["x-tx-hash"];
    if (paymentTx) {
      const verification = await verifyBaseTransaction(paymentTx, payee, priceUsdc);
      if (verification.valid) {
        req.authContext = {
          method: "x402_onchain",
          txHash: paymentTx,
          network: "base",
          amountUsdc: priceUsdc,
        };
        return next();
      } else {
        return res.status(400).json({
          status: 400,
          error: "Payment Verification Failed",
          reason: verification.reason,
        });
      }
    }

    // 5. Emit HTTP 402 Payment Required with x402 Protocol headers
    res.setHeader("X-Accept-Currency", "USDC");
    res.setHeader("X-Price", priceUsdc);
    res.setHeader("X-Pay-To", payee);
    res.setHeader("X-Chain-ID", "8453");
    res.setHeader("X-Token-Contract", BASE_USDC_CONTRACT);

    return res.status(402).json({
      status: 402,
      error: "Payment Required",
      message: "This endpoint requires an active RapidAPI subscription or an on-chain x402 USDC micropayment on Base.",
      x402: {
        version: "1.0.0",
        network: "base",
        chain_id: 8453,
        currency: "USDC",
        token_contract: BASE_USDC_CONTRACT,
        payee,
        amount: priceUsdc,
        instruction: `Transfer ${priceUsdc} USDC to ${payee} on Base (Chain ID 8453), then resend your request with header 'X-Payment-Tx: <tx_hash>'.`,
      },
      rapidapi: {
        marketplace_url: "https://rapidapi.com/simultech/api/ai-shield-gateway",
      },
    });
  };
}
