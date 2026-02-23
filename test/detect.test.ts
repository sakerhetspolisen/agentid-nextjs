import { describe, it, expect } from "vitest";
import { isAgentRequest, extractToken } from "../src/detect.js";

function h(init: Record<string, string> = {}): Headers {
  return new Headers(init);
}

// ── isAgentRequest ───────────────────────────────────────────────────────────

describe("isAgentRequest", () => {
  it("returns false for a typical Chrome browser request", () => {
    expect(
      isAgentRequest(
        h({
          "user-agent":
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
          "accept-language": "en-US,en;q=0.9",
        })
      )
    ).toBe(false);
  });

  it("returns false for Firefox with accept-language", () => {
    expect(
      isAgentRequest(
        h({
          "user-agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
          "accept-language": "sv-SE",
        })
      )
    ).toBe(false);
  });

  // Known AI/bot agents
  it.each([
    ["GPTBot/1.0", "OpenAI GPTBot"],
    ["ChatGPT-User/1.0", "OpenAI ChatGPT-User"],
    ["ClaudeBot/1.0 (+https://anthropic.com)", "Anthropic ClaudeBot"],
    ["anthropic-ai/1.0", "Anthropic SDK"],
    ["Googlebot/2.1", "Google crawler"],
    ["bingbot/2.0", "Microsoft Bing"],
    ["PerplexityBot/1.0", "Perplexity"],
    ["python-requests/2.31.0", "Python requests"],
    ["node-fetch/1.0 (+https://github.com/bitinn/node-fetch)", "node-fetch"],
    ["axios/1.6.2", "axios"],
    ["curl/7.88.1", "curl"],
    ["wget/1.21.4", "wget"],
    ["mcp-client/1.0", "MCP client"],
  ])("returns true for %s (%s)", (ua) => {
    expect(isAgentRequest(h({ "user-agent": ua }))).toBe(true);
  });

  it("returns true for a missing User-Agent", () => {
    expect(isAgentRequest(h({}))).toBe(true);
  });

  it("returns true for an empty User-Agent", () => {
    expect(isAgentRequest(h({ "user-agent": "" }))).toBe(true);
  });

  it("returns true for a non-browser UA with no Accept-Language", () => {
    expect(
      isAgentRequest(h({ "user-agent": "MyCustomAgent/1.0" }))
    ).toBe(true);
  });

  it("returns false for a non-browser UA WITH Accept-Language (conservative)", () => {
    // A custom UA that sends Accept-Language is treated as human (fail open)
    expect(
      isAgentRequest(
        h({
          "user-agent": "MyCustomAgent/1.0",
          "accept-language": "en",
        })
      )
    ).toBe(false);
  });
});

// ── extractToken ─────────────────────────────────────────────────────────────

describe("extractToken", () => {
  it("extracts token from Authorization: Bearer header", () => {
    expect(
      extractToken(h({ authorization: "Bearer abc.def.ghi" }))
    ).toBe("abc.def.ghi");
  });

  it("extracts token from X-AgentID-Token header (fallback)", () => {
    expect(
      extractToken(h({ "x-agentid-token": "abc.def.ghi" }))
    ).toBe("abc.def.ghi");
  });

  it("prefers Authorization over X-AgentID-Token", () => {
    expect(
      extractToken(
        h({
          authorization: "Bearer primary-token",
          "x-agentid-token": "fallback-token",
        })
      )
    ).toBe("primary-token");
  });

  it("returns null when no token is present", () => {
    expect(extractToken(h({}))).toBeNull();
  });

  it("returns null for 'Authorization: Bearer ' with empty token", () => {
    expect(extractToken(h({ authorization: "Bearer " }))).toBeNull();
  });

  it("returns null for non-Bearer Authorization schemes", () => {
    expect(
      extractToken(h({ authorization: "Basic dXNlcjpwYXNz" }))
    ).toBeNull();
  });

  it("trims whitespace from the token", () => {
    expect(
      extractToken(h({ "x-agentid-token": "  my.token.here  " }))
    ).toBe("my.token.here");
  });
});
