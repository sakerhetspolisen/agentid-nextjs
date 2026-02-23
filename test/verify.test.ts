import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { verifyAgentIDToken } from "../src/verify.js";

// ── Test key pair ────────────────────────────────────────────────────────────

let privateKey: CryptoKey;
let kidKey: Record<string, unknown>;

const TEST_JWKS_URL = "https://localhost/api/jwks";

// Stub global fetch BEFORE the module cache initialises (module-level call).
const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);

beforeAll(async () => {
  const { privateKey: pk, publicKey: pub } = await generateKeyPair("RS256", {
    modulusLength: 2048,
  });
  privateKey = pk;

  const jwk = await exportJWK(pub);
  kidKey = { ...jwk, kid: "test-key-1", alg: "RS256", use: "sig" };

  fetchMock.mockImplementation(async (url: string | URL) => {
    if (url.toString() === TEST_JWKS_URL) {
      return new Response(JSON.stringify({ keys: [kidKey] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    throw new Error(`[test] Unexpected fetch: ${url}`);
  });
});

// ── Helpers ──────────────────────────────────────────────────────────────────

async function makeToken(
  extraPayload: Record<string, unknown> = {},
  opts: { expiresIn?: string; issuer?: string; kid?: string } = {}
) {
  return new SignJWT({ auth_method: "bankid", ...extraPayload })
    .setProtectedHeader({ alg: "RS256", kid: opts.kid ?? "test-key-1" })
    .setIssuer(opts.issuer ?? "agentid")
    .setSubject("abc123pseudosub")
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .setExpirationTime(opts.expiresIn ?? "1h")
    .sign(privateKey);
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("verifyAgentIDToken", () => {
  it("verifies a valid token and returns claims", async () => {
    const token = await makeToken();
    const claims = await verifyAgentIDToken(token, { jwksUrl: TEST_JWKS_URL });

    expect(claims.auth_method).toBe("bankid");
    expect(claims.iss).toBe("agentid");
    expect(claims.sub).toBe("abc123pseudosub");
    expect(typeof claims.exp).toBe("number");
    expect(typeof claims.jti).toBe("string");
  });

  it("rejects a token with the wrong issuer", async () => {
    const token = await makeToken({}, { issuer: "evil.com" });
    await expect(
      verifyAgentIDToken(token, { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const token = await makeToken({}, { expiresIn: "-2m" });
    await expect(
      verifyAgentIDToken(token, { jwksUrl: TEST_JWKS_URL, clockTolerance: 0 })
    ).rejects.toThrow();
  });

  it("rejects a token with missing auth_method", async () => {
    // Override auth_method with undefined by not setting it
    const token = await new SignJWT({ not_auth_method: true })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-1" })
      .setIssuer("agentid")
      .setSubject("abc")
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .setExpirationTime("1h")
      .sign(privateKey);

    await expect(
      verifyAgentIDToken(token, { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow("auth_method");
  });

  it("rejects a token with an invalid auth_method value", async () => {
    const token = await makeToken({ auth_method: "password" });
    await expect(
      verifyAgentIDToken(token, { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow("auth_method");
  });

  it("rejects a non-HTTPS jwksUrl (MITM prevention)", async () => {
    const token = await makeToken();
    await expect(
      verifyAgentIDToken(token, { jwksUrl: "http://attacker.com/api/jwks" })
    ).rejects.toThrow("must use HTTPS");
  });

  it("allows localhost JWKS URLs for local development", async () => {
    const token = await makeToken();
    // Should NOT throw the HTTPS error (may throw for other reasons in test)
    await expect(
      verifyAgentIDToken(token, {
        jwksUrl: "http://localhost:3000/api/jwks",
      })
    ).rejects.not.toThrow("must use HTTPS");
  });

  it("rejects a malformed JWT string", async () => {
    await expect(
      verifyAgentIDToken("not.a.jwt", { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow();
  });

  it("rejects an empty string", async () => {
    await expect(
      verifyAgentIDToken("", { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow();
  });
});

// ── Security: algorithm-confusion attacks ────────────────────────────────────

describe("algorithm confusion attack prevention", () => {
  it("rejects alg:none tokens (critical — no signature means no auth)", async () => {
    // jose does not allow signing with alg:none, so we hand-craft the JWT.
    const header = Buffer.from(JSON.stringify({ alg: "none", kid: "test-key-1" }))
      .toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        iss: "agentid",
        sub: "hacker",
        auth_method: "bankid",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        jti: "fake",
      })
    ).toString("base64url");
    const noneToken = `${header}.${payload}.`; // empty signature

    await expect(
      verifyAgentIDToken(noneToken, { jwksUrl: TEST_JWKS_URL })
    ).rejects.toThrow();
  });
});
