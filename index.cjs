"use strict";

const { createHash, randomBytes } = require("node:crypto");
const bundledModels = require("./models.json");
const MODEL_CATALOG_URL = "https://raw.githubusercontent.com/neelsatyavolu/shared-ai-auth/main/models.json";

const providers = Object.freeze({
  codex: Object.freeze({
    clientId: "app_EMoamEEZ73f0CkXaXp7hrann",
    redirectUri: "http://localhost:1455/auth/callback",
    authorizeUrl: "https://auth.openai.com/oauth/authorize",
    tokenUrl: "https://auth.openai.com/oauth/token",
    scope: "openid profile email offline_access",
    expirySkew: 60,
    extraAuthorizeParams: {
      id_token_add_organizations: "true",
      codex_cli_simplified_flow: "true",
      originator: "codex_cli_rs",
    },
  }),
  claude: Object.freeze({
    // Claude Code's claude.ai sign-in (a Pro or Max subscription). The callback page shows
    // `code#state` for the user to paste; there is no localhost listener.
    clientId: "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    redirectUri: "https://platform.claude.com/oauth/code/callback",
    authorizeUrl: "https://claude.com/cai/oauth/authorize",
    tokenUrl: "https://platform.claude.com/v1/oauth/token",
    scope: "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload",
    expirySkew: 300,
    tokenFormat: "json",
    extraAuthorizeParams: { code: "true" },
  }),
  grok: Object.freeze({
    clientId: "b1a00492-073a-47ea-816f-4c329264a828",
    redirectUri: "http://127.0.0.1:56121/callback",
    authorizeUrl: "https://auth.x.ai/oauth2/authorize",
    tokenUrl: "https://auth.x.ai/oauth2/token",
    scope: "openid profile email offline_access grok-cli:access api:access",
    expirySkew: 120,
    extraAuthorizeParams: {},
  }),
});

function config(provider) {
  if (!Object.hasOwn(providers, provider)) throw new Error(`Unknown OAuth provider: ${provider}`);
  return providers[provider];
}

function generatePkce() {
  const verifier = randomBytes(64).toString("base64url");
  return {
    verifier,
    challenge: createHash("sha256").update(verifier).digest("base64url"),
    state: randomBytes(32).toString("base64url"),
  };
}

function authorizeUrl(provider, pkce) {
  const cfg = config(provider);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectUri,
    scope: cfg.scope,
    code_challenge: pkce.challenge,
    code_challenge_method: "S256",
    state: pkce.state,
    ...cfg.extraAuthorizeParams,
  });
  return `${cfg.authorizeUrl}?${params}`;
}

function parseCallback(input) {
  const value = String(input ?? "").trim().replace(/^['"]|['"]$/g, "");
  if (!value) return { code: null, state: null, error: null };
  try {
    if (value.includes("://") || value.startsWith("?") || /(?:^|[&?])(?:code|state|error)=/.test(value)) {
      const params = value.includes("://") ? new URL(value).searchParams : new URLSearchParams(value.replace(/^\?/, ""));
      return { code: params.get("code"), state: params.get("state"), error: params.get("error") };
    }
  } catch {
    return { code: null, state: null, error: "invalid_callback" };
  }
  // Claude's callback page shows `code#state`.
  const hash = value.indexOf("#");
  if (hash > 0) return { code: value.slice(0, hash), state: value.slice(hash + 1) || null, error: null };
  return { code: value, state: null, error: null };
}

function codexAccountId(idToken) {
  try {
    const payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"));
    const orgs = payload?.["https://api.openai.com/auth"]?.organizations;
    if (Array.isArray(orgs) && orgs.length) return (orgs.find((org) => org?.is_default) ?? orgs[0])?.id;
    return payload?.sub;
  } catch {
    return undefined;
  }
}

async function tokenRequest(provider, body, options = {}) {
  const cfg = config(provider);
  const json = cfg.tokenFormat === "json";
  const response = await (options.fetch ?? fetch)(cfg.tokenUrl, {
    method: "POST",
    headers: { "content-type": json ? "application/json" : "application/x-www-form-urlencoded" },
    body: json ? JSON.stringify(Object.fromEntries(body)) : body.toString(),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`${provider} token request failed (${response.status})`);
  const data = await response.json();
  if (typeof data.access_token !== "string" || !data.access_token) throw new Error(`${provider} token response has no access token`);
  const refreshToken = data.refresh_token ?? options.previous?.refreshToken;
  if (typeof refreshToken !== "string" || !refreshToken) throw new Error(`${provider} token response has no refresh token`);
  const expiresIn = Number(data.expires_in);
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new Error(`${provider} token response has invalid expiry`);
  return {
    accessToken: data.access_token,
    refreshToken,
    idToken: data.id_token ?? options.previous?.idToken,
    accountId: provider === "codex" ? codexAccountId(data.id_token) ?? options.previous?.accountId : undefined,
    expiresAt: Date.now() + Math.max(30, expiresIn - cfg.expirySkew) * 1000,
  };
}

function exchangeCode(provider, code, verifier, options = {}) {
  const cfg = config(provider);
  // Claude's token endpoint also wants the state the callback page showed with the code.
  if (provider === "claude" && !options.state) return Promise.reject(new Error("claude needs the state from its callback (code#state)"));
  return tokenRequest(provider, new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId, code_verifier: verifier,
    ...(provider === "claude" ? { state: options.state } : {}),
  }), options);
}

function refreshTokens(provider, refreshToken, options = {}) {
  const cfg = config(provider);
  return tokenRequest(provider, new URLSearchParams({
    grant_type: "refresh_token", refresh_token: refreshToken,
    client_id: cfg.clientId, scope: cfg.scope,
  }), { ...options, previous: { ...options.previous, refreshToken } });
}

function validList(list) {
  return Array.isArray(list) && list.length > 0 && list.every((model) =>
    model && typeof model.id === "string" && model.id.length > 0 && typeof model.label === "string" && model.label.length > 0);
}

/** codex and grok are required; claude, added later, is checked when present so older catalogs stay valid. */
function validModels(value) {
  return Boolean(value && value.version === 1 && validList(value.codex) && validList(value.grok) && (value.claude === undefined || validList(value.claude)));
}

async function loadModels({ url = MODEL_CATALOG_URL, fallback = bundledModels, fetch: fetcher = fetch } = {}) {
  if (!validModels(fallback)) throw new Error("A valid fallback model catalog is required");
  try {
    const response = await fetcher(url, { signal: AbortSignal.timeout(5000), cache: "no-store" });
    if (!response.ok) return fallback;
    const json = await response.json();
    return validModels(json) ? json : fallback;
  } catch {
    return fallback;
  }
}

function selectModels(catalog, provider, hiddenIds = []) {
  config(provider);
  if (!validModels(catalog)) throw new Error("Invalid model catalog");
  const hidden = new Set(hiddenIds);
  return (catalog[provider] ?? []).filter((model) => !hidden.has(model.id));
}

/*
 * Claude subscription requests. Anthropic's subscription backend serves OAuth tokens only for
 * requests shaped like Claude Code's: the OAuth beta header, a claude-cli user agent and, as the
 * first system block, a billing line derived from the first user message and the advertised
 * Claude Code version. The same adaptation as pi-claude-oauth-adapter (MIT).
 */
const CLAUDE_CODE_VERSION = "2.1.322";
const CLAUDE_BILLING_SALT = "59cf53e54c78";
const CLAUDE_IDENTITY = "You are Claude Code, Anthropic's official CLI for Claude.";
const CLAUDE_MESSAGES_URL = "https://api.anthropic.com/v1/messages";

function textOf(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.filter((b) => b && b.type === "text" && typeof b.text === "string").map((b) => b.text).join("\n");
}

function claudeBillingLine(messages, version = CLAUDE_CODE_VERSION, entrypoint = "cli") {
  const first = (Array.isArray(messages) ? messages : []).find((m) => m && m.role === "user");
  const text = first ? textOf(first.content) : "";
  const sampled = [4, 7, 20].map((i) => text[i] ?? "0").join("");
  const hash = createHash("sha256").update(`${CLAUDE_BILLING_SALT}${sampled}${version}`).digest("hex").slice(0, 3);
  return `x-anthropic-billing-header: cc_version=${version}.${hash}; cc_entrypoint=${entrypoint}; cch=00000;`;
}

/**
 * Turns an Anthropic Messages request body into one a Claude subscription token can send:
 * returns the URL, headers and body. Extra beta flags in `options.betas` are kept.
 */
function claudeRequest(body, options = {}) {
  if (!options.accessToken) throw new Error("claudeRequest needs an access token");
  const version = options.version ?? CLAUDE_CODE_VERSION;
  const entrypoint = options.entrypoint ?? "cli";
  const given = typeof body.system === "string" ? [{ type: "text", text: body.system }] : Array.isArray(body.system) ? body.system : [];
  const blocks = given.filter((b) => b && b.type === "text" && b.text !== CLAUDE_IDENTITY && !String(b.text).startsWith("x-anthropic-billing-header:"));
  const system = [{ type: "text", text: claudeBillingLine(body.messages, version, entrypoint) }, ...blocks];
  const betas = ["oauth-2025-04-20", ...(options.betas ?? [])];
  return {
    url: options.url ?? CLAUDE_MESSAGES_URL,
    headers: {
      authorization: `Bearer ${options.accessToken}`,
      "anthropic-version": "2023-06-01",
      "anthropic-beta": [...new Set(betas)].join(","),
      "content-type": "application/json",
      "user-agent": `claude-cli/${version} (external, ${entrypoint})`,
      "x-app": "cli",
    },
    body: { ...body, system },
  };
}

/** The Claude Code version Anthropic demands in a "version X or newer is required" error, if any. */
function claudeRequiredVersion(message) {
  const m = /version\s+(\d+(?:\.\d+)+)\s+or\s+newer\s+is\s+required/i.exec(String(message ?? ""));
  return m ? m[1] : null;
}

module.exports = {
  providers, MODEL_CATALOG_URL, bundledModels, generatePkce, authorizeUrl, parseCallback, exchangeCode, refreshTokens, loadModels, selectModels,
  CLAUDE_CODE_VERSION, claudeRequest, claudeRequiredVersion,
};
