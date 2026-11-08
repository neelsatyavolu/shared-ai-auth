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
    extraAuthorizeParams: Object.freeze({
      id_token_add_organizations: "true",
      codex_cli_simplified_flow: "true",
      originator: "codex_cli_rs",
    }),
  }),
  grok: Object.freeze({
    clientId: "b1a00492-073a-47ea-816f-4c329264a828",
    redirectUri: "http://127.0.0.1:56121/callback",
    authorizeUrl: "https://auth.x.ai/oauth2/authorize",
    tokenUrl: "https://auth.x.ai/oauth2/token",
    scope: "openid profile email offline_access grok-cli:access api:access",
    expirySkew: 120,
    // plan=generic is required; xAI rejects loopback OAuth for this client without it.
    extraAuthorizeParams: Object.freeze({ plan: "generic" }),
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

function unwrapCallback(input) {
  let value = String(input ?? "").trim();
  for (let i = 0; i < 2; i += 1) {
    const next = value.replace(/^['"]|['"]$/g, "").replace(/^<|>$/g, "").trim();
    if (next === value) break;
    value = next;
  }
  return value;
}

function callbackParams(value) {
  // OAuth codes are opaque. URLSearchParams would treat "+" as a space and corrupt them.
  const query = value.includes("://") ? new URL(value).search : value;
  return new URLSearchParams(query.replace(/^\?/, "").replace(/\+/g, "%2B"));
}

function parseCallback(input) {
  const value = unwrapCallback(input);
  if (!value) return { code: null, state: null, error: null };
  try {
    if (value.includes("://") || value.startsWith("?") || /(?:^|[&?])(?:code|state|error)=/.test(value)) {
      const params = callbackParams(value);
      return { code: params.get("code"), state: params.get("state"), error: params.get("error") };
    }
  } catch {
    return { code: null, state: null, error: "invalid_callback" };
  }
  return { code: value, state: null, error: null };
}

function nonEmptyString(value) {
  return typeof value === "string" && value ? value : undefined;
}

function jwtPayload(token) {
  if (typeof token !== "string") return undefined;
  const part = token.split(".")[1];
  if (!part) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return payload && typeof payload === "object" ? payload : undefined;
  } catch {
    return undefined;
  }
}

function chatgptAccountId(token) {
  const payload = jwtPayload(token);
  if (!payload) return undefined;
  const auth = payload["https://api.openai.com/auth"];
  return nonEmptyString(auth?.chatgpt_account_id) ?? nonEmptyString(payload.chatgpt_account_id);
}

async function tokenRequest(provider, body, options = {}) {
  const cfg = config(provider);
  const response = await (options.fetch ?? fetch)(cfg.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) {
    const reason = await oauthErrorCode(response);
    throw new Error(`${provider} token request failed (${response.status}${reason ? `: ${reason}` : ""})`);
  }
  const json = await response.json();
  if (!json || typeof json !== "object") throw new Error(`${provider} token response is invalid`);
  if (typeof json.access_token !== "string" || !json.access_token) throw new Error(`${provider} token response has no access token`);
  const refreshToken = nonEmptyString(json.refresh_token) ?? nonEmptyString(options.previous?.refreshToken);
  if (!refreshToken) throw new Error(`${provider} token response has no refresh token`);
  const expiresIn = Number(json.expires_in);
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new Error(`${provider} token response has invalid expiry`);
  // Keep the early-refresh floor, but never report the token as valid after it actually expires.
  const lifetime = Math.min(expiresIn, Math.max(30, expiresIn - cfg.expirySkew));
  return {
    accessToken: json.access_token,
    refreshToken,
    idToken: nonEmptyString(json.id_token) ?? nonEmptyString(options.previous?.idToken),
    accountId: provider === "codex"
      ? chatgptAccountId(json.id_token) ?? chatgptAccountId(json.access_token) ?? nonEmptyString(options.previous?.accountId)
      : undefined,
    expiresAt: Date.now() + lifetime * 1000,
  };
}

async function oauthErrorCode(response) {
  try {
    if (typeof response.json !== "function") return "";
    const body = await response.json();
    const code = body && typeof body === "object" ? body.error : "";
    return typeof code === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(code) ? code : "";
  } catch {
    return "";
  }
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

function selectModels(catalog, provider, hiddenIds = []) {
  config(provider);
  if (!validModels(catalog)) throw new Error("Invalid model catalog");
  const hidden = new Set(hiddenIds);
  return catalog[provider].filter((model) => !hidden.has(model.id));
}

module.exports = { providers, MODEL_CATALOG_URL, bundledModels, generatePkce, authorizeUrl, parseCallback, exchangeCode, refreshTokens, loadModels, selectModels };
