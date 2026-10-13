import assert from "node:assert/strict";
import test from "node:test";
import {
  providers, bundledModels, generatePkce, authorizeUrl, parseCallback,
  exchangeCode, refreshTokens, loadModels, selectModels,
} from "../index.mjs";

test("bundled catalog offers only the five selected models", () => {
  assert.deepEqual(bundledModels.codex.map((model) => model.id), ["gpt-6-astra", "gpt-6.1-sol", "gpt-6-luna"]);
  assert.deepEqual(bundledModels.grok.map((model) => model.id), ["grok-4.7", "grok-4.6"]);
});

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
  assert.equal(new URL(authorizeUrl("grok", pkce)).searchParams.get("plan"), "generic");
  assert.equal(new URL(authorizeUrl("codex", pkce)).searchParams.get("plan"), null);
  assert.equal(Object.isFrozen(providers.codex.extraAuthorizeParams), true);
  assert.throws(() => { providers.grok.extraAuthorizeParams.plan = "other"; }, TypeError);
});

test("callback parsing accepts URL, query, and Grok pasted code", () => {
  assert.deepEqual(parseCallback("http://localhost:1455/auth/callback?code=abc&state=xyz"), { code: "abc", state: "xyz", error: null });
  assert.deepEqual(parseCallback("?code=a%2Bb&state=s"), { code: "a+b", state: "s", error: null });
  assert.deepEqual(parseCallback("?code=a+b&state=s"), { code: "a+b", state: "s", error: null });
  assert.deepEqual(parseCallback("<http://localhost:1455/auth/callback?code=a+b&state=s>"), { code: "a+b", state: "s", error: null });
  assert.deepEqual(parseCallback('"<http://localhost:1455/auth/callback?code=abc&state=xyz>"'), { code: "abc", state: "xyz", error: null });
  assert.deepEqual(parseCallback("bare-code"), { code: "bare-code", state: null, error: null });
  assert.deepEqual(parseCallback("?error=access_denied"), { code: null, state: null, error: "access_denied" });
});

test("exchange and refresh use provider endpoints and preserve account and refresh token", async () => {
  const calls = [];
  const token = `x.${Buffer.from(JSON.stringify({
    sub: "user-sub",
    "https://api.openai.com/auth": {
      chatgpt_account_id: "acct",
      organizations: [{ id: "org-default", is_default: true }],
    },
  })).toString("base64url")}.y`;
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
  assert.equal(second.idToken, token);
  const lifetime = first.expiresAt - Date.now();
  assert.ok(lifetime <= 3540_000 && lifetime > 3540_000 - 1000);
});

test("codex account id is the auth claim, not the organization id or subject", async () => {
  const idToken = `x.${Buffer.from(JSON.stringify({
    sub: "user-sub",
    "https://api.openai.com/auth": { organizations: [{ id: "org-default", is_default: true }] },
  })).toString("base64url")}.y`;
  const accessToken = `x.${Buffer.from(JSON.stringify({
    chatgpt_account_id: "acct-access",
  })).toString("base64url")}.y`;
  const fetcher = async () => ({
    ok: true,
    json: async () => ({ access_token: accessToken, refresh_token: "r", expires_in: 3600, id_token: idToken }),
  });
  const tokens = await exchangeCode("codex", "code", "verifier", { fetch: fetcher });
  assert.equal(tokens.accountId, "acct-access");
});

test("refresh keeps previous tokens when the provider sends blanks", async () => {
  const idToken = `x.${Buffer.from(JSON.stringify({
    "https://api.openai.com/auth": { chatgpt_account_id: "acct" },
  })).toString("base64url")}.y`;
  const previous = { accessToken: "a", refreshToken: "kept", expiresAt: 1, idToken, accountId: "acct" };
  const fetcher = async () => ({
    ok: true,
    json: async () => ({ access_token: "b", refresh_token: "", expires_in: 3600, id_token: "" }),
  });
  const next = await refreshTokens("codex", "kept", { fetch: fetcher, previous });
  assert.equal(next.refreshToken, "kept");
  assert.equal(next.idToken, idToken);
  assert.equal(next.accountId, "acct");
});

test("short token lifetimes are not extended past the real expiry", async () => {
  const fetcher = async () => ({ ok: true, json: async () => ({ access_token: "a", refresh_token: "r", expires_in: 10 }) });
  const before = Date.now();
  const tokens = await exchangeCode("grok", "code", "verifier", { fetch: fetcher });
  const after = Date.now();
  assert.ok(tokens.expiresAt >= before + 10_000);
  assert.ok(tokens.expiresAt <= after + 10_000);
});

test("token failures surface the oauth error code without the description", async () => {
  const fetcher = async () => ({
    ok: false,
    status: 400,
    json: async () => ({ error: "invalid_grant", error_description: "refresh token secret-value" }),
  });
  await assert.rejects(
    () => refreshTokens("codex", "r", { fetch: fetcher }),
    (error) => {
      assert.match(error.message, /^codex token request failed \(400: invalid_grant\)$/);
      assert.equal(error.message.includes("secret-value"), false);
      return true;
    },
  );
  const noBody = async () => ({ ok: false, status: 503 });
  await assert.rejects(() => exchangeCode("grok", "code", "verifier", { fetch: noBody }), /grok token request failed \(503\)$/);
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

test("hidden models are removed while new catalog models remain visible", () => {
  const catalog = { version: 1, codex: [{ id: "old", label: "Old" }, { id: "new", label: "New" }], grok: [{ id: "grok", label: "Grok" }] };
  assert.deepEqual(selectModels(catalog, "codex", ["old"]).map((model) => model.id), ["new"]);
  assert.deepEqual(selectModels(catalog, "grok", ["old"]).map((model) => model.id), ["grok"]);
});
