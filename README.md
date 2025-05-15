# h3-oauth-kit

A type-safe, multi-provider OAuth 2.0 toolkit for [H3](https://github.com/unjs/h3) apps.
Handles login, callback, token refresh, and protected route middleware — all with automatic cookie storage and typed provider extensions.

> ⚠️ **This package is experimental and currently supports a small number of providers (`azure`, `clio`, `intuit`).**
> It's built for internal use but is published publicly for ease of consumption and iteration.

---

## Features

- 🔐 OAuth 2.0 Authorization Code flow support
- 🍞 Token storage via secure, HTTP-only cookies
- 🔁 Automatic token refresh on protected routes
- 🧠 State validation & metadata preservation
- 🛠️ Utility-first API with full TypeScript safety

---

## Installation

```bash
npm install @sasha-milenkovic/h3-oauth-kit
```

Or using yarn:

```bash
yarn add @sasha-milenkovic/h3-oauth-kit
```

Or using pnpm:

```bash
pnpm add @sasha-milenkovic/h3-oauth-kit
```

---

## API Overview

### `registerOAuthProvider(provider, confg)`

```ts
import { registerOAuthProvider } from "@sasha-milenkovic/h3-oauth-kit";

registerOAuthProvider("azure", {
  clientId: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",
  redirectUri: "http://localhost:3000/api/auth/azure/callback",
  tokenEndpoint: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
  authorizeEndpoint:
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
  scopes: ["openid", "profile", "email"],
});
```

---

### `handleOAuthLogin(provider, options?, event?)`

- Can be used as a route handler or utility.
- Supports automatic or manual redirection.
- If state is not provided, a unique identifier is automatically generated.

#### Route Handler (redirects immediately):

```ts
export default handleOAuthLogin("azure", { redirect: true });
```

#### Utility Usage (e.g. to customize redirect)

```ts
import { defineEventHandler, getQuery } from "h3";
import { handleOAuthLogin } from "@sasha-milenkovic/h3-oauth-kit";

export default defineEventHandler(async (event) => {
  return await handleOAuthLogin(
    "azure",
    {
      state: (event) => {
        const { redirectTo } = getQuery(event);
        return {
          redirectTo: redirectTo ?? "/",
          requestId: crypto.randomUUID(),
        };
      },
    },
    event
  );
});
```

---

### `handleOAuthCallback(provider, options?, event?)`

- Exchanges code for tokens, verifies state, and stores tokens in cookies.
- Can auto-redirect or return structured result.

#### Route Handler (with redirect):

```ts
export default handleOAuthCallback("azure", {
  redirectTo: "/dashboard",
});
```

#### Utility Usage (custom logic after callback):

This example demonstrates how to handle the callback, where `state` represents the data passed during login (or the state provided by the OAuth provider), and `callbackQueryData` contains additional data returned by the provider:

```ts
import { defineEventHandler, sendRedirect } from "h3";
import { handleOAuthCallback } from "@sasha-milenkovic/h3-oauth-kit";

export default defineEventHandler(async (event) => {
  const { state, callbackQueryData } = await handleOAuthCallback(
    "azure",
    { redirect: false },
    event
  );

  return sendRedirect(event, state.redirectTo || "/");
});
```

---

### `defineProtectedRoute(providers, handler, options?)`

- Declares that one or more providers **must be authenticated** before the route handler runs.
- Automatically checks cookie presence and token freshness.
- If expired, the access token is refreshed (if possible).
- If tokens are missing or invalid, a `401` is returned.
- Injects validated token data into `event.context`, including:

  - `event.context.azure_access_token` (just the access token)
  - `event.context.h3OAuthKit.azure` (full token structure, strongly typed)

#### Example:

```ts
export default defineProtectedRoute(["azure"], async (event) => {
  return {
    message: "You're authenticated with Azure!",
    token: event.context.h3OAuthKit.azure,
  };
});
```

> 💡 This is especially powerful because all tokens are type-safe — you get full IntelliSense and validation for each provider's token fields.

---

## Tokens & Cookies

- Access tokens stored in: `*_access_token`
- Expiration (absolute): `*_access_token_expires_at`
- Refresh tokens (optional): `*_refresh_token`
- Custom provider fields: e.g., `azure_ext_expires_in`, `azure_token_type`

---

## Provider Configuration

You can define provider-specific behavior (e.g., which fields to store as cookies) via `providerConfig`. Fields like `token_type`, `ext_expires_in`, or `id_token` can be persisted automatically across sessions and refreshes.

These custom fields are automatically read and rehydrated as part of the token refresh and route protection workflows.

---

## Type Safety

Each method is fully typed for provider-specific behavior:

- All tokens returned are strongly typed by provider.
- Token cookies and refresh responses are parsed into provider-aware shapes.
- Context is augmented in protected routes:

  ```ts
  event.context.h3OAuthKit.azure; // full Azure token object
  event.context.azure_access_token; // just the raw access token string
  ```

This makes integration seamless and safe across complex authentication workflows.

---

## License

[MIT](./LICENSE)

---

## Author

Made with ❤️ by [@sasha-milenkovic](https://github.com/sasha-milenkovic)
