import assert from "node:assert/strict";
import test from "node:test";
import {
  providers, bundledModels, generatePkce, authorizeUrl, parseCallback,
  exchangeCode, refreshTokens, loadModels, selectModels,
  CLAUDE_CODE_VERSION, claudeRequest, claudeRequiredVersion,
} from "../index.mjs";
import { createHash } from "node:crypto";

test("bundled catalog offers only the six selected models", () => {
  assert.deepEqual(bundledModels.codex.map((model) => model.id), ["gpt-6.2-astra", "gpt-6.2-sol", "gpt-6.1-terra", "gpt-6-luna"]);
  assert.deepEqual(bundledModels.grok.map((model) => model.id), ["grok-4.7", "grok-4.6"]);
  assert.deepEqual(bundledModels.claude.map((model) => model.id), ["claude-fable-5-2", "claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"]);
});

test("each bundled model lists its efforts, and a bad efforts list makes the catalog invalid", async () => {
  for (const model of [...bundledModels.codex, ...bundledModels.grok, ...bundledModels.claude]) assert.ok(model.efforts.length > 0, model.id);
  assert.deepEqual(bundledModels.codex[0].efforts, ["low", "medium", "high", "xhigh", "max", "ultra"]);
  const remote = { version: 1, codex: [{ id: "a", label: "A", efforts: [] }], grok: [{ id: "g", label: "G" }] };
  const loaded = await loadModels({ url: "https://example.test/models.json", fetch: async () => ({ ok: true, json: async () => remote }) });
  assert.equal(loaded, bundledModels);
});

test("claude signs in at claude.com with the manual callback and code=true", () => {
  const pkce = generatePkce();
  const url = new URL(authorizeUrl("claude", pkce));
  assert.equal(url.origin + url.pathname, "https://claude.com/cai/oauth/authorize");
  assert.equal(url.searchParams.get("code"), "true");
  assert.equal(url.searchParams.get("redirect_uri"), "https://platform.claude.com/oauth/code/callback");
  assert.match(url.searchParams.get("scope"), /user:inference/);
  assert.deepEqual(parseCallback("the-code#the-state"), { code: "the-code", state: "the-state", error: null });
});

test("claude token requests are JSON and carry the state", async () => {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push({ url, type: init.headers["content-type"], body: JSON.parse(init.body) });
    return { ok: true, json: async () => ({ access_token: "sk-ant-oat01-a", refresh_token: "sk-ant-ort01-r", expires_in: 28800 }) };
  };
  await assert.rejects(exchangeCode("claude", "c", "v", { fetch: fetcher }), /state/);
  const tokens = await exchangeCode("claude", "c", "v", { fetch: fetcher, state: "s" });
  assert.equal(calls[0].url, "https://platform.claude.com/v1/oauth/token");
  assert.equal(calls[0].type, "application/json");
  assert.deepEqual(calls[0].body, { grant_type: "authorization_code", code: "c", redirect_uri: providers.claude.redirectUri, client_id: providers.claude.clientId, code_verifier: "v", state: "s" });
  await refreshTokens("claude", tokens.refreshToken, { fetch: fetcher, previous: tokens });
  assert.equal(calls[1].body.grant_type, "refresh_token");
  assert.equal(calls[1].body.scope, providers.claude.scope);
});

test("claudeRequest adds the billing line and OAuth headers and drops the identity line", () => {
  const body = { model: "claude-sonnet-5-5", system: [{ type: "text", text: "You are Claude Code, Anthropic's official CLI for Claude." }, { type: "text", text: "You are Perch." }], messages: [{ role: "user", content: [{ type: "text", text: "Find the cheapest SSD" }] }] };
  const out = claudeRequest(body, { accessToken: "tok", betas: ["fast-mode-2026-02-01"] });
  const sampled = ["Find the cheapest SSD"[4], "Find the cheapest SSD"[7], "Find the cheapest SSD"[20]].join("");
  const hash = createHash("sha256").update(`59cf53e54c78${sampled}${CLAUDE_CODE_VERSION}`).digest("hex").slice(0, 3);
  assert.deepEqual(out.body.system.map((b) => b.text), [`x-anthropic-billing-header: cc_version=${CLAUDE_CODE_VERSION}.${hash}; cc_entrypoint=cli; cch=00000;`, "You are Perch."]);
  assert.equal(out.headers.authorization, "Bearer tok");
  assert.equal(out.headers["anthropic-beta"], "oauth-2025-04-20,fast-mode-2026-02-01");
  assert.equal(out.headers["user-agent"], `claude-cli/${CLAUDE_CODE_VERSION} (external, cli)`);
  assert.equal(out.url, "https://api.anthropic.com/v1/messages");
  assert.equal(body.system.length, 2, "the input body is not changed");
  assert.equal(claudeRequest({ system: "Plain", messages: [] }, { accessToken: "t" }).body.system[1].text, "Plain");
  assert.equal(claudeRequiredVersion("Claude Code 2.1.226 does not support this model; version 2.1.251 or newer is required."), "2.1.251");
  assert.equal(claudeRequiredVersion("overloaded"), null);
});

test("older catalogs without claude stay valid", async () => {
  const old = { version: 1, codex: [{ id: "a", label: "A" }], grok: [{ id: "g", label: "G" }] };
  const loaded = await loadModels({ url: "https://example.test/m.json", fetch: async () => ({ ok: true, json: async () => old }) });
  assert.deepEqual(loaded, old);
  assert.deepEqual(selectModels(old, "claude"), []);
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

test("hidden models are removed while new catalog models remain visible", () => {
  const catalog = { version: 1, codex: [{ id: "old", label: "Old" }, { id: "new", label: "New" }], grok: [{ id: "grok", label: "Grok" }] };
  assert.deepEqual(selectModels(catalog, "codex", ["old"]).map((model) => model.id), ["new"]);
  assert.deepEqual(selectModels(catalog, "grok", ["old"]).map((model) => model.id), ["grok"]);
});
