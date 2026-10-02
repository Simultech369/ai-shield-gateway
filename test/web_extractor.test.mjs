import assert from "node:assert/strict";
import { htmlToMarkdown, validateSafeUrl } from "../src/engine/web_extractor.mjs";

console.log("=== Testing Web-to-Markdown Extractor Engine ===");

// 1. SSRF prevention
const blocked1 = validateSafeUrl("http://localhost:3000/api");
assert.equal(blocked1.valid, false);

const blocked2 = validateSafeUrl("http://127.0.0.1:8000");
assert.equal(blocked2.valid, false);

const blocked3 = validateSafeUrl("http://192.168.1.1");
assert.equal(blocked3.valid, false);

const blocked4 = validateSafeUrl("file:///etc/passwd");
assert.equal(blocked4.valid, false);

const allowed = validateSafeUrl("https://news.ycombinator.com");
assert.equal(allowed.valid, true);
console.log("✔ SSRF filters correctly block internal & dangerous URLs");

// 2. HTML to Markdown parsing
const sampleHtml = `
<!DOCTYPE html>
<html>
<head>
  <title>Deep Dive into AI Agents</title>
  <meta name="description" content="An in-depth article on autonomous agent architectures.">
  <meta name="author" content="Josh">
</head>
<body>
  <nav><a href="/home">Home</a><a href="/about">About</a></nav>
  <article>
    <h1>Autonomous Agent Invariants</h1>
    <p>Agents must maintain deterministic state boundaries. See <a href="https://github.com/Simultech369">Simultech Repos</a> for details.</p>
    <h2>Key Capabilities</h2>
    <ul>
      <li>Privacy Preserving LLM Proxy</li>
      <li>Cryptographic Citation Grounding</li>
    </ul>
    <pre><code>function verify() { return true; }</code></pre>
    <blockquote>Integrity is non-negotiable.</blockquote>
  </article>
  <footer>Copyright 2026</footer>
</body>
</html>
`;

const res = htmlToMarkdown(sampleHtml);
assert.equal(res.title, "Deep Dive into AI Agents");
assert.equal(res.author, "Josh");
assert.equal(res.description, "An in-depth article on autonomous agent architectures.");
assert(res.markdown.includes("# Autonomous Agent Invariants"));
assert(res.markdown.includes("[Simultech Repos](https://github.com/Simultech369)"));
assert(res.markdown.includes("* Privacy Preserving LLM Proxy"));
assert(res.markdown.includes("```\nfunction verify() { return true; }\n```"));
assert(res.markdown.includes("> Integrity is non-negotiable."));
assert(!res.markdown.includes("Copyright 2026")); // Footer stripped
assert(!res.markdown.includes("Home")); // Nav stripped
assert(res.content_sha256.length === 64);
assert(res.word_count > 10);
assert(res.estimated_tokens > 5);

console.log("✔ Clean semantic markdown extracted with metadata & boilerplate stripped");
console.log("ALL EXTRACTOR TESTS PASSED CLEANLY!");
