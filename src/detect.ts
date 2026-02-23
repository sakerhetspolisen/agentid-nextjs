/**
 * Bot / AI-agent detection for Next.js (Edge Runtime compatible).
 *
 * Uses layered heuristics:
 *  1. Explicit bot / AI-agent User-Agent strings
 *  2. Absence of browser signals (no Accept-Language + non-browser UA)
 *
 * The detector is intentionally conservative — when in doubt it lets the
 * request through (fail open). A false negative (undetected bot) means the
 * request passes without a JWT check. A false positive (human flagged as bot)
 * would block legitimate traffic, which is much worse.
 */

const BOT_UA_PATTERNS: RegExp[] = [
  // OpenAI
  /GPTBot/i,
  /ChatGPT-User/i,
  /OAI-SearchBot/i,
  // Anthropic / Claude
  /ClaudeBot/i,
  /Claude-Web/i,
  /anthropic-ai/i,
  /Claude-User/i,
  // Google
  /Googlebot/i,
  /Google-Extended/i,
  /AdsBot-Google/i,
  // Microsoft / Bing
  /bingbot/i,
  /msnbot/i,
  // AI search engines
  /PerplexityBot/i,
  /YouBot/i,
  // Common HTTP automation libraries
  /python-requests/i,
  /node-fetch/i,
  /\baxios\b/i,
  /\bgot\b\//i,
  /\bundici\b/i,
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bhttpie\b/i,
  // Generic crawler signals (word-boundary matched to reduce false positives)
  /\bbot\b/i,
  /\bcrawler\b/i,
  /\bspider\b/i,
  /\bscraper\b/i,
  /\bfetcher\b/i,
  // MCP / AgentID clients
  /mcp-client/i,
  /agentid-client/i,
];

// Every major browser includes "Mozilla/5.0" — its absence is a strong signal
const BROWSER_UA_RE = /Mozilla\/5\.0/i;

/**
 * Returns `true` if the request appears to originate from an automated
 * agent or bot rather than a human browser.
 *
 * @param headers - The `Headers` object from a Next.js `NextRequest`
 */
export function isAgentRequest(headers: Headers): boolean {
  const ua = headers.get("user-agent") ?? "";

  // No User-Agent → definitely automated
  if (!ua) return true;

  // Explicit bot / agent UA match
  if (BOT_UA_PATTERNS.some((p) => p.test(ua))) return true;

  // Heuristic: non-browser UA + no Accept-Language → likely automated
  if (!BROWSER_UA_RE.test(ua) && !headers.get("accept-language")) return true;

  return false;
}

/**
 * Extract the AgentID JWT from request headers.
 *
 * Checks in order:
 *  1. `Authorization: Bearer <token>` (preferred)
 *  2. `X-AgentID-Token` (fallback when Authorization is stripped by proxies)
 *
 * @returns The raw JWT string, or `null` if absent.
 */
export function extractToken(headers: Headers): string | null {
  // Primary: standard Authorization header
  const auth = headers.get("authorization") ?? "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    if (token) return token;
  }

  // Fallback: custom header
  const custom = headers.get("x-agentid-token")?.trim();
  if (custom) return custom;

  return null;
}
