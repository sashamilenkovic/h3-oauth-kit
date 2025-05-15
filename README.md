# h3-oauth-kit

A type-safe, multi-provider OAuth 2.0 toolkit for [H3](https://github.com/unjs/h3) apps.  
Handles login, callback, token refresh, and protected route middleware — all with automatic cookie storage and typed provider extensions.

> ⚠️ **This package is experimental and currently supports a small number of providers (`clio`, `azure`, `intuit`).**  
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

## Quick Start

### 1. Register your OAuth provider

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

## API Overview

### `handleOAuthLogin(provider, options?, event?)`

- Can be used as a route handler or utility.
- Supports automatic or manual redirection.

#### Route Handler (redirects immediately):

```ts
export default handleOAuthLogin("clio", { redirect: true });
```

#### Utility Usage (e.g. to customize redirect)

```ts
export default defineEventHandler(async (event) => {
  const { url } = await handleOAuthLogin("clio", {}, event);
  return sendRedirect(event, url);
});
```

---

### `handleOAuthCallback(provider, options?, event?)`

- Exchanges code for tokens, verifies state, and stores tokens in cookies.
- Can auto-redirect or return structured result.

#### Route Handler (with redirect):

```ts
export default handleOAuthCallback("clio", {
  redirectTo: "/dashboard",
});
```

#### Utility Usage (custom logic after callback):

```ts
export default defineEventHandler(async (event) => {
  const { tokens, state } = await handleOAuthCallback(
    "clio",
    { redirect: false },
    event
  );
  const redirectTo =
    typeof state === "object" && state?.from ? state.from : "/";
  return sendRedirect(event, redirectTo);
});
```

---

### `defineProtectedRoute(providers, handler, options?)`

- Validates tokens from cookies.
- Automatically refreshes if expired.
- Injects tokens into `event.context`:

  - `event.context.clio_access_token`
  - `event.context.h3OAuthKit.clio`

#### Example:

```ts
export default defineProtectedRoute(["clio"], async (event) => {
  return {
    message: "You're authenticated!",
    token: event.context.h3OAuthKit.clio,
  };
});
```

---

## Tokens & Cookies

- Access tokens stored in: `*_access_token`
- Expiration (absolute): `*_access_token_expires_at`
- Refresh tokens (optional): `*_refresh_token`
- Custom provider fields: e.g., `clio_client_id`, `azure_ext_expires_in`

---

## Provider Configuration

You can define provider-specific behavior (e.g., which fields to store as cookies) via `providerConfig`. Fields like `token_type`, `client_id`, `realm_id` can be persisted automatically across sessions and refreshes.

---

## Type Safety

Each method is fully typed for provider-specific behavior:

- All tokens returned are strongly typed by provider.
- You can access token fields directly and safely from `event.context.h3OAuthKit`.

---

## License

[MIT](./LICENSE)

---

## Author

Made with ❤️ by [@sasha-milenkovic](https://github.com/sasha-milenkovic)
