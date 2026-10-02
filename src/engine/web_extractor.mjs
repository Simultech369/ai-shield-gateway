import * as cheerio from "cheerio";
import crypto from "node:crypto";

const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^169\.254\.\d{1,3}\.\d{1,3}$/,
  /^0\.0\.0\.0$/,
  /^::1$/,
];

export function validateSafeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: "Malformed URL" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { valid: false, reason: "Only HTTP and HTTPS protocols are allowed" };
  }

  const hostname = parsed.hostname;
  for (const pattern of PRIVATE_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      return { valid: false, reason: `Access to internal host '${hostname}' is disallowed` };
    }
  }

  return { valid: true, url: parsed.toString() };
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text ?? ""), "utf8").digest("hex");
}

export function htmlToMarkdown(html, options = {}) {
  const $ = cheerio.load(html);

  // Extract metadata
  const title = $("title").first().text().trim() ||
                $('meta[property="og:title"]').attr("content") ||
                $('meta[name="twitter:title"]').attr("content") || "";

  const description = $('meta[name="description"]').attr("content") ||
                      $('meta[property="og:description"]').attr("content") ||
                      $('meta[name="twitter:description"]').attr("content") || "";

  const author = $('meta[name="author"]').attr("content") ||
                 $('meta[property="article:author"]').attr("content") || "";

  const canonical = $('link[rel="canonical"]').attr("href") || "";

  // Strip boilerplate and non-content tags
  $(
    "script, style, noscript, nav, footer, iframe, svg, [role='banner'], [role='navigation'], " +
    ".ads, .advertisement, #cookie-banner, .cookie-notice, .footer, .header, .nav, .sidebar"
  ).remove();

  // Target main content container if available
  let $root = $("article");
  if (!$root.length) $root = $("main");
  if (!$root.length) $root = $("[role='main']");
  if (!$root.length) $root = $("#content");
  if (!$root.length) $root = $(".content");
  if (!$root.length) $root = $("body");

  // Replace links with markdown links
  $root.find("a").each((_, el) => {
    const $el = $(el);
    const href = $el.attr("href");
    const text = $el.text().trim();
    if (href && text && !href.startsWith("javascript:")) {
      $el.replaceWith(` [${text}](${href}) `);
    } else {
      $el.replaceWith(text);
    }
  });

  // Replace images
  if (options.include_images) {
    $root.find("img").each((_, el) => {
      const $el = $(el);
      const src = $el.attr("src");
      const alt = $el.attr("alt") || "image";
      if (src) {
        $el.replaceWith(` ![${alt}](${src}) `);
      }
    });
  } else {
    $root.find("img").remove();
  }

  // Headings
  $root.find("h1").each((_, el) => { const $el = $(el); $el.replaceWith(`\n\n# ${$el.text().trim()}\n\n`); });
  $root.find("h2").each((_, el) => { const $el = $(el); $el.replaceWith(`\n\n## ${$el.text().trim()}\n\n`); });
  $root.find("h3").each((_, el) => { const $el = $(el); $el.replaceWith(`\n\n### ${$el.text().trim()}\n\n`); });
  $root.find("h4, h5, h6").each((_, el) => { const $el = $(el); $el.replaceWith(`\n\n#### ${$el.text().trim()}\n\n`); });

  // Code blocks
  $root.find("pre").each((_, el) => {
    const $el = $(el);
    const code = $el.text().trim();
    $el.replaceWith(`\n\n\`\`\`\n${code}\n\`\`\`\n\n`);
  });
  $root.find("code").each((_, el) => {
    const $el = $(el);
    if ($el.parent("pre").length === 0) {
      $el.replaceWith(` \`${$el.text().trim()}\` `);
    }
  });

  // Blockquotes
  $root.find("blockquote").each((_, el) => {
    const $el = $(el);
    const quote = $el.text().trim().split("\n").map(line => `> ${line.trim()}`).join("\n");
    $el.replaceWith(`\n\n${quote}\n\n`);
  });

  // Lists
  $root.find("li").each((_, el) => {
    const $el = $(el);
    $el.replaceWith(`\n* ${$el.text().trim()}`);
  });

  // Paragraphs and divs
  $root.find("p").each((_, el) => {
    const $el = $(el);
    $el.replaceWith(`\n\n${$el.text().trim()}\n\n`);
  });
  $root.find("br").replaceWith("\n");

  // Clean up whitespace
  let markdown = $root.text();
  markdown = markdown
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (options.max_chars && markdown.length > options.max_chars) {
    markdown = markdown.slice(0, options.max_chars) + "\n\n...[truncated]";
  }

  const wordCount = markdown ? markdown.split(/\s+/).length : 0;
  const estimatedTokens = Math.ceil(markdown.length / 4);

  return {
    title,
    description,
    author,
    canonical_url: canonical,
    markdown,
    word_count: wordCount,
    estimated_tokens: estimatedTokens,
    content_sha256: sha256Hex(markdown),
  };
}

export async function extractUrlToMarkdown(url, options = {}) {
  const safe = validateSafeUrl(url);
  if (!safe.valid) {
    throw new Error(`SSRF Blocked: ${safe.reason}`);
  }

  const timeoutMs = options.timeout_ms || 10000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(safe.url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (AI-Agent-Extractor/1.0)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    if (!response.ok) {
      throw new Error(`Upstream fetch returned HTTP ${response.status}: ${response.statusText}`);
    }

    const html = await response.text();
    const result = htmlToMarkdown(html, options);
    return {
      url: safe.url,
      ...result,
      fetched_at: new Date().toISOString(),
    };
  } finally {
    clearTimeout(timer);
  }
}
