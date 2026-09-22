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
  const response = await (options.fetch ?? fetch)(cfg.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!response.ok) throw new Error(`${provider} token request failed (${response.status})`);
  const json = await response.json();
  if (typeof json.access_token !== "string" || !json.access_token) throw new Error(`${provider} token response has no access token`);
  const refreshToken = json.refresh_token ?? options.previous?.refreshToken;
  if (typeof refreshToken !== "string" || !refreshToken) throw new Error(`${provider} token response has no refresh token`);
  const expiresIn = Number(json.expires_in);
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new Error(`${provider} token response has invalid expiry`);
  return {
    accessToken: json.access_token,
    refreshToken,
    idToken: json.id_token ?? options.previous?.idToken,
    accountId: provider === "codex" ? codexAccountId(json.id_token) ?? options.previous?.accountId : undefined,
    expiresAt: Date.now() + Math.max(30, expiresIn - cfg.expirySkew) * 1000,
  };
}

function exchangeCode(provider, code, verifier, options = {}) {
  const cfg = config(provider);
  return tokenRequest(provider, new URLSearchParams({
    grant_type: "authorization_code", code, redirect_uri: cfg.redirectUri,
    client_id: cfg.clientId, code_verifier: verifier,
  }), options);
}

function refreshTokens(provider, refreshToken, options = {}) {
  const cfg = config(provider);
  return tokenRequest(provider, new URLSearchParams({
    grant_type: "refresh_token", refresh_token: refreshToken,
    client_id: cfg.clientId, scope: cfg.scope,
  }), { ...options, previous: { ...options.previous, refreshToken } });
}

function validModels(value) {
  return value && value.version === 1 && ["codex", "grok"].every((provider) =>
    Array.isArray(value[provider]) && value[provider].length > 0 && value[provider].every((model) =>
      model && typeof model.id === "string" && model.id.length > 0 && typeof model.label === "string" && model.label.length > 0));
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

module.exports = { providers, MODEL_CATALOG_URL, bundledModels, generatePkce, authorizeUrl, parseCallback, exchangeCode, refreshTokens, loadModels };
