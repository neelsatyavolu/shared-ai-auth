# Shared Codex and Grok sign-in

This package holds the Codex and Grok OAuth client settings and PKCE/token helpers used by Neel's Node web and Electron apps. Apps own their callback listener or pasted-code UI and their secure token storage. The same package works from ESM and CommonJS.

`models.json` is the single editable model list. Already deployed apps can refresh it from `MODEL_CATALOG_URL`; `loadModels()` returns the bundled snapshot if the public file is unavailable or invalid. Call it on the server or in the desktop main process, and cache the result for a few minutes in the app. Do not fetch OAuth tokens or the model catalog from an untrusted URL.

Install from the public GitHub repository, then use:

```js
import { generatePkce, authorizeUrl, parseCallback, exchangeCode, refreshTokens, loadModels } from "@neelsatyavolu/shared-ai-auth";

const pkce = generatePkce();
const signInUrl = authorizeUrl("codex", pkce);
// Persist verifier and state for this attempt in an app-owned session.
const callback = parseCallback(pastedUrl);
if (callback.error || callback.state !== pkce.state || !callback.code) throw new Error("Invalid sign-in response");
const tokens = await exchangeCode("codex", callback.code, pkce.verifier);
const catalog = await loadModels();
```

For Grok, use `"grok"` and accept its bare authorization code when the provider displays one. A bare code has no state; bind it to the pending local PKCE attempt. Keep refresh tokens in the app's existing secure store. Call `refreshTokens(provider, token, { previous: savedTokens })` to preserve a rotated or omitted refresh token and the Codex account ID.

The listed OAuth client IDs and redirect URIs belong to the existing CLI flows. Verify provider terms and current endpoints before changing them. This helper does not register a new OAuth application or host callbacks.
