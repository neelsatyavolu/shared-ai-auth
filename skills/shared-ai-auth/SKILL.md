---
name: shared-ai-auth
description: Use when adding or changing Codex or Grok subscription OAuth, callback handling, token refresh, or selectable model lists in Neel's web and desktop apps.
---

# Shared Codex and Grok auth

Use the public `neelsatyavolu/shared-ai-auth` repository as the shared source. Its Node package exports provider configuration, PKCE, authorization URL, callback parser, token exchange, refresh, and a live model catalog loader. `models.json` in that repository is the one editable model list. The public catalog URL is exported as `MODEL_CATALOG_URL`.

For Node web apps and Electron main processes, import the package instead of copying client IDs, redirect URIs, scopes, and token request code. Keep callback route/listener, pending state/verifier, cookies or Keychain, and AI request code in the app. Verify state for URL callbacks; Grok's displayed bare code has no state and must be associated with one pending local attempt. Store tokens only in the app's existing secure store.

For model pickers, use the full catalog or apply a project-level ID blacklist with `selectModels`. An ID is visible by default, so newly published models appear automatically unless a project explicitly blacklists them.

For native Swift/Rust apps, use the same public JSON catalog with a bundled fallback and preserve their native OAuth and Keychain logic. Do not add a Node runtime to a native app solely to share auth. A model list update should modify `models.json`, validate its schema and model IDs against the intended provider, then publish that file; deployed clients refresh it without rebuilding. Keep bounded network timeouts, validate JSON, and retain the last known good or bundled list if offline.

Before changing a project, inspect its callback mode (pasted URL/code versus loopback), token persistence, account ID handling, model picker, and tests. Preserve these behaviors. Do not change unrelated provider integrations. Do not print auth codes, access tokens, refresh tokens, or callback URLs in logs or skill output.
