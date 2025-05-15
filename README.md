# h3-oauth-kit

A type-safe, multi-provider OAuth 2.0 toolkit for [H3](https://github.com/unjs/h3) apps.  
Handles login, callback, token refresh, and protected route middleware — all with automatic cookie storage and typed provider extensions.

> ⚠️ **This package is experimental and currently supports a small number of providers (`clio`, `azure`, `intuit`).**  
> It's built for internal use but is published publicly for ease of consumption and iteration.

---

## Features

- 🔐 OAuth 2.0 Authorization Code flow support
- 🍪 Token storage via secure, HTTP-only cookies
- 🔁 Automatic token refresh on protected routes
- 🧠 State validation & metadata preservation
- 🧰 Utility-first API with full TypeScript safety

---

## Installation

```bash
npm install @sasha-milenkovic/h3-oauth-kit
```

---

## Example Usage

Below are common usage patterns for registering a provider, handling login and callback, and protecting routes.

#### Register a Provider

Before using any login, callback, or route protection helpers, register your provider:

```ts
import { registerOAuthProvider } from "@sasha-milenkovic/h3-oauth-kit";

registerOAuthProvider("clio", {
  clientId: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",
  redirectUri: "http://localhost:3000/api/auth/clio/callback",
  tokenEndpoint: "https://app.clio.com/oauth/token",
  authorizeEndpoint: "https://app.clio.com/oauth/authorize",
  scopes: ["openid"],
});
```

---

#### Login Handler

```ts
// server/api/auth/clio/login.ts
import { handleOAuthLogin } from "@sasha-milenkovic/h3-oauth-kit";

export default handleOAuthLogin("clio", { redirect: true });
```

#### Custom Login Handler

```ts
// server/api/auth/clio/custom-login.ts
import { handleOAuthLogin } from "@sasha-milenkovic/h3-oauth-kit";

export default defineEventHandler(async (event) => {
  const { url } = await handleOAuthLogin("clio", {}, event);
  return sendRedirect(event, url, 302);
});
```

#### Callback Handler

```ts
// server/api/auth/clio/callback.ts
import { handleOAuthCallback } from "@sasha-milenkovic/h3-oauth-kit";

export default handleOAuthCallback("clio", {
  redirectTo: "/dashboard",
});
```

#### Custom Callback Handler

```ts
// server/api/auth/clio/custom-callback.ts
import { handleOAuthCallback } from "@sasha-milenkovic/h3-oauth-kit";

export default defineEventHandler(async (event) => {
  const { tokens, state, callbackQueryData } = await handleOAuthCallback(
    "clio",
    { redirect: false },
    event
  );

  // Example: use `state.from` or other state values to determine redirect
  const redirectPath =
    typeof state === "object" && state?.from ? String(state.from) : "/";

  return sendRedirect(event, redirectPath);
});
```

#### Protecting a Route

```ts
// server/api/secure-data.ts
import { defineProtectedRoute } from "@sasha-milenkovic/h3-oauth-kit";

export default defineProtectedRoute(["clio"], async (event) => {
  const accessToken = event.context.clio_access_token;
  const fullToken = event.context.h3OAuthKit.clio;

  return {
    message: "Protected content",
    accessToken,
    tokenDetails: fullToken,
  };
});
```
