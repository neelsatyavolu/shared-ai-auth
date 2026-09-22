import assert from "node:assert/strict";
import test from "node:test";
import {
  providers, generatePkce, authorizeUrl, parseCallback,
  exchangeCode, refreshTokens, loadModels,
} from "../index.mjs";

test("both providers generate an S256 authorization URL with their own redirect", () => {
  const pkce = generatePkce();
  assert.match(pkce.verifier, /^[A-Za-z0-9_-]+$/);
  for (const provider of ["codex", "grok"]) {
    const url = new URL(authorizeUrl(provider, pkce));
    assert.equal(url.searchParams.get("client_id"), providers[provider].clientId);
    assert.equal(url.searchParams.get("redirect_uri"), providers[provider].redirectUri);
    assert.equal(url.searchParams.get("code_challenge"), pkce.challenge);
    assert.equal(url.searchParams.get("state"), pkce.state);
  }
});

test("callback parsing accepts URL, query, and Grok pasted code", () => {
  assert.deepEqual(parseCallback("http://localhost:1455/auth/callback?code=abc&state=xyz"), { code: "abc", state: "xyz", error: null });
  assert.deepEqual(parseCallback("?code=a%2Bb&state=s"), { code: "a+b", state: "s", error: null });
  assert.deepEqual(parseCallback("bare-code"), { code: "bare-code", state: null, error: null });
  assert.deepEqual(parseCallback("?error=access_denied"), { code: null, state: null, error: "access_denied" });
});

test("exchange and refresh use provider endpoints and preserve account and refresh token", async () => {
  const calls = [];
  const token = `x.${Buffer.from(JSON.stringify({ sub: "acct" })).toString("base64url")}.y`;
  const fetcher = async (url, init) => {
    calls.push({ url, form: new URLSearchParams(init.body) });
    return { ok: true, json: async () => calls.length === 1
      ? { access_token: "a", refresh_token: "r", expires_in: 3600, id_token: token }
      : { access_token: "b", expires_in: 3600 } };
  };
  const first = await exchangeCode("codex", "code", "verifier", { fetch: fetcher });
  assert.equal(first.accountId, "acct");
  assert.equal(calls[0].form.get("redirect_uri"), providers.codex.redirectUri);
  const second = await refreshTokens("codex", first.refreshToken, { fetch: fetcher, previous: first });
  assert.equal(second.refreshToken, "r");
  assert.equal(second.accountId, "acct");
});

test("model loading validates remote data and uses bundled fallback on failure", async () => {
  const fallback = { version: 1, codex: [{ id: "old", label: "Old" }], grok: [{ id: "grok", label: "Grok" }] };
  const remote = { version: 1, codex: [{ id: "new", label: "New" }], grok: [{ id: "grok", label: "Grok" }] };
  const loaded = await loadModels({ url: "https://example.test/models.json", fallback, fetch: async () => ({ ok: true, json: async () => remote }) });
  assert.deepEqual(loaded, remote);
  const failed = await loadModels({ url: "https://example.test/models.json", fallback, fetch: async () => { throw new Error("offline"); } });
  assert.deepEqual(failed, fallback);
  const invalid = await loadModels({ url: "https://example.test/models.json", fallback, fetch: async () => ({ ok: true, json: async () => ({ codex: [] }) }) });
  assert.deepEqual(invalid, fallback);
});
