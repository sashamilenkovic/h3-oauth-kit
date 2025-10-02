# h3-oauth-kit

[![codecov](https://codecov.io/github/sashamilenkovic/h3-oauth-kit/graph/badge.svg?token=Y4JAJQWYCQ)](https://codecov.io/github/sashamilenkovic/h3-oauth-kit)
![Run Vitest](https://github.com/sashamilenkovic/h3-oauth-kit/actions/workflows/ci.yml/badge.svg)

A type-safe, multi-provider OAuth 2.0 toolkit for [H3](https://github.com/unjs/h3) apps.
Handles login, callback, token refresh, and protected route middleware — all with automatic cookie storage and typed provider extensions.

> **Built-in providers:** `azure`, `clio`, `intuit`, `mycase`  
> **Custom providers:** Add support for any OAuth 2.0 provider (Google, GitHub, Facebook, etc.) with full type safety via module augmentation.  
> See [CUSTOM_PROVIDERS.md](./CUSTOM_PROVIDERS.md) for details.

---

## Features

- 🔐 OAuth 2.0 Authorization Code flow support
- 🍞 Token storage via secure, HTTP-only cookies
- 🔁 Automatic token refresh on protected routes
- 🧠 State validation & metadata preservation
- 🛠️ Utility-first API with full TypeScript safety
- 🎨 Extensible type system for custom OAuth providers
- 🏢 Multi-tenant / multi-instance support

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

## Environment Variables

To enable secure encryption of refresh tokens, you must define the following environment variable:

```bash
H3_OAUTH_ENCRYPTION_KEY=your_64_char_hex_string
```

This must be a 64-character hex string, which corresponds to a 32-byte encryption key for AES-256-CBC.

You can generate a key using Node.js:

```ts
crypto.randomBytes(32).toString('hex');
```

⚠️ H3_OAUTH_ENCRYPTION_KEY is required. If it's missing or invalid, the package will throw an error at runtime.

---

## Custom OAuth Providers

**NEW in v0.12.0!** Add support for any OAuth 2.0 provider with full type safety.

```typescript
// types/h3-oauth-kit.d.ts
declare module '@sasha-milenkovic/h3-oauth-kit' {
  interface CustomOAuthProviders {
    google: 'google';
  }
  interface CustomProviderTokenMap {
    google: GoogleAuthTokens;
  }
  // ... other type maps
}

// server/plugins/oauthProviders.ts
registerOAuthProvider('google', {
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  authorizeEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenEndpoint: 'https://oauth2.googleapis.com/token',
  redirectUri: 'http://localhost:3000/api/auth/google/callback',
  scopes: ['openid', 'email', 'profile'],
});

// Use exactly like built-in providers - no `as any` needed!
export default defineProtectedRoute(['google'], async (event) => {
  const token = event.context.h3OAuthKit.google.access_token;
  // Full type safety!
});
```

📖 **[Read the full Custom Providers guide](./CUSTOM_PROVIDERS.md)** for Google, GitHub, Facebook, and more.

---

## API Overview

### `registerOAuthProvider(provider, config)` / `registerOAuthProvider(provider, instanceKey, config)`

Registers an OAuth provider configuration. Supports both **global** and **scoped** (multi-tenant) configurations.

#### Global Registration (Single-Tenant)

```ts
import { registerOAuthProvider } from '@sasha-milenkovic/h3-oauth-kit';

registerOAuthProvider('azure', {
  clientId: 'YOUR_CLIENT_ID',
  clientSecret: 'YOUR_CLIENT_SECRET',
  redirectUri: 'http://localhost:3000/api/auth/azure/callback',
  tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
  authorizeEndpoint:
    'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
  scopes: ['openid', 'profile', 'email'],
});
```

#### Scoped Registration (Multi-Tenant)

For multi-tenant applications, you can register multiple configurations for the same provider using an `instanceKey`:

```ts
// Register different Azure configurations for different tenants
registerOAuthProvider('azure', 'tenant-a', {
  clientId: 'TENANT_A_CLIENT_ID',
  clientSecret: 'TENANT_A_CLIENT_SECRET',
  redirectUri: 'http://localhost:3000/api/auth/azure/callback',
  tokenEndpoint: 'https://login.microsoftonline.com/tenant-a/oauth2/v2.0/token',
  authorizeEndpoint:
    'https://login.microsoftonline.com/tenant-a/oauth2/v2.0/authorize',
  scopes: ['openid', 'profile', 'email'],
});

registerOAuthProvider('azure', 'tenant-b', {
  clientId: 'TENANT_B_CLIENT_ID',
  clientSecret: 'TENANT_B_CLIENT_SECRET',
  redirectUri: 'http://localhost:3000/api/auth/azure/callback',
  tokenEndpoint: 'https://login.microsoftonline.com/tenant-b/oauth2/v2.0/token',
  authorizeEndpoint:
    'https://login.microsoftonline.com/tenant-b/oauth2/v2.0/authorize',
  scopes: ['openid', 'profile', 'email'],
});

// Or register different Clio configurations for different law firms
registerOAuthProvider('clio', 'smithlaw', {
  clientId: 'SMITHLAW_CLIENT_ID',
  clientSecret: 'SMITHLAW_CLIENT_SECRET',
  // ... other config
});

registerOAuthProvider('clio', 'johnsonlegal', {
  clientId: 'JOHNSONLEGAL_CLIENT_ID',
  clientSecret: 'JOHNSONLEGAL_CLIENT_SECRET',
  // ... other config
});
```

---

### `handleOAuthLogin(provider, options?, event?)` / `handleOAuthLogin(provider, instanceKey, options?, event?)`

- Can be used as a route handler or utility.
- Supports automatic or manual redirection.
- Supports both global and scoped (multi-tenant) provider configurations.
- If state is not provided, a unique identifier is automatically generated.

#### Global Provider Usage

```ts
// Route Handler (redirects immediately)
export default handleOAuthLogin('azure', { redirect: true });

// Utility Usage (returns URL for manual redirect)
const { url } = await handleOAuthLogin('azure', {}, event);
```

#### Scoped Provider Usage (Multi-Tenant)

```ts
// Route Handler for specific tenant
export default handleOAuthLogin('azure', 'tenant-a', { redirect: true });

// Utility Usage for specific law firm
const { url } = await handleOAuthLogin('clio', 'smithlaw', {}, event);
```

#### Advanced Usage with Custom State

```ts
import { defineEventHandler, getQuery } from 'h3';
import { handleOAuthLogin } from '@sasha-milenkovic/h3-oauth-kit';

export default defineEventHandler(async (event) => {
  const { tenant } = getQuery(event);

  return await handleOAuthLogin(
    'azure',
    tenant as string, // Use dynamic instanceKey
    {
      state: (event) => {
        const { redirectTo } = getQuery(event);
        return {
          redirectTo: redirectTo ?? '/',
          requestId: crypto.randomUUID(),
        };
      },
    },
    event,
  );
});
```

---

### `handleOAuthCallback(provider, options?, event?)`

- Exchanges code for tokens, verifies state, and stores tokens in cookies.
- Can auto-redirect or return structured result.
- **Automatically detects scoped providers** from the state parameter (no need to pass instanceKey manually).

#### Route Handler (with redirect):

```ts
// Works for both global and scoped providers
export default handleOAuthCallback('azure', {
  redirectTo: '/dashboard',
});
```

#### Utility Usage (custom logic after callback):

This example demonstrates how to handle the callback, where `state` represents the data passed during login (including `instanceKey` for scoped providers), and `callbackQueryData` contains additional data returned by the provider:

```ts
import { defineEventHandler, sendRedirect } from 'h3';
import { handleOAuthCallback } from '@sasha-milenkovic/h3-oauth-kit';

export default defineEventHandler(async (event) => {
  const { state, callbackQueryData } = await handleOAuthCallback(
    'azure',
    { redirect: false },
    event,
  );

  return sendRedirect(event, state.redirectTo || '/');
});
```

---

### `defineProtectedRoute(providers, handler, options?)`

- Declares that one or more providers **must be authenticated** before the route handler runs.
- Automatically checks cookie presence and token freshness.
- If expired, the access token is refreshed (if possible).
- If tokens are missing or invalid, a `401` is returned.
- **Supports both global and scoped (multi-tenant) providers**.
- Injects validated token data into `event.context.h3OAuthKit` with type-safe provider keys.

#### Global Provider Example:

```ts
import { defineProtectedRoute } from '@sasha-milenkovic/h3-oauth-kit';

export default defineProtectedRoute(['azure'], async (event) => {
  const token = event.context.h3OAuthKit.azure.access_token;

  try {
    return await $fetch(`https://graph.microsoft.com/v1.0/me`, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch (error) {
    console.error('Error fetching azure user profile:', error);
    throw error;
  }
});
```

#### Scoped Provider Example (Multi-Tenant):

```ts
import { defineProtectedRoute } from '@sasha-milenkovic/h3-oauth-kit';

export default defineProtectedRoute(
  [
    { provider: 'azure', instanceKey: 'tenant-a' },
    { provider: 'clio', instanceKey: 'smithlaw' },
  ],
  async (event) => {
    // Access tokens for specific instances (note the bracket notation for scoped keys)
    const azureToken = event.context.h3OAuthKit['azure:tenant-a'].access_token;
    const clioToken = event.context.h3OAuthKit['clio:smithlaw'].access_token;

    // Make API calls with instance-specific tokens
    const [azureProfile, clioUser] = await Promise.all([
      $fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${azureToken}` },
      }),
      $fetch('https://app.clio.com/api/v4/users/who_am_i.json', {
        headers: { Authorization: `Bearer ${clioToken}` },
      }),
    ]);

    return { azureProfile, clioUser };
  },
);
```

#### Mixed Global and Scoped Providers:

```ts
export default defineProtectedRoute(
  [
    'azure', // Global azure config
    { provider: 'clio', instanceKey: 'smithlaw' }, // Scoped clio config
  ],
  async (event) => {
    const globalAzureToken = event.context.h3OAuthKit.azure.access_token;
    const scopedClioToken =
      event.context.h3OAuthKit['clio:smithlaw'].access_token;

    // Use both tokens...
  },
);
```

> 💡 This is especially powerful because all tokens are type-safe — you get full IntelliSense and validation for each provider's token fields, and the context keys automatically reflect whether you're using global (`azure`) or scoped (`azure:tenant-a`) providers.

#### Accessing Resolved Instance Keys

When using `withInstanceKeys` for dynamic instance resolution, you can access the resolved instance keys directly from the event context via `h3OAuthKitInstances`. This provides full type safety and eliminates the need to re-extract router parameters:

```ts
import {
  defineProtectedRoute,
  withInstanceKeys,
} from '@sasha-milenkovic/h3-oauth-kit';
import { getRouterParams, createError } from 'h3';

const getClioAccountIds = () => ['123', '12345', '123456'];
const isValidClioAccountId = (id: string) => getClioAccountIds().includes(id);

export default defineProtectedRoute(
  [
    'azure',
    withInstanceKeys('clio', getClioAccountIds(), (event) => {
      const { clioId } = getRouterParams(event);

      if (!clioId) {
        throw createError({
          statusCode: 400,
          message: 'Clio account ID is required',
        });
      }

      if (!isValidClioAccountId(clioId)) {
        throw createError({
          statusCode: 400,
          message: 'Invalid Clio account ID',
        });
      }

      return clioId; // Returns typed instance key
    }),
  ],
  async (event) => {
    // ✨ NEW: Access the typed instance key directly from context!
    const clioId = event.context.h3OAuthKitInstances.clio; // Type: "123" | "12345" | "123456"

    // No need to re-extract from router params!
    if (!clioId) {
      throw createError({ statusCode: 400, message: 'Missing clio instance' });
    }

    // This now works with full type safety!
    const clioTokens = event.context.h3OAuthKit[`clio:${clioId}`];
    const azureTokens = event.context.h3OAuthKit.azure;

    return {
      clioId, // Fully typed as "123" | "12345" | "123456"
      hasClioTokens: !!clioTokens,
      hasAzureTokens: !!azureTokens,
    };
  },
);
```

**Benefits:**

- ✅ **Full type safety** - TypeScript knows the exact possible instance keys
- ✅ **No re-extraction needed** - The resolved key is already validated and typed
- ✅ **Zero breaking changes** - Existing code continues to work
- ✅ **Better developer experience** - IntelliSense shows available instance keys

**Context Properties:**

```ts
// For global providers
event.context.h3OAuthKitInstances.azure; // undefined (no instance key)

// For scoped providers with explicit instanceKey
event.context.h3OAuthKitInstances.clio; // "smithlaw" (from { provider: "clio", instanceKey: "smithlaw" })

// For scoped providers with withInstanceKeys resolver
event.context.h3OAuthKitInstances.clio; // "123" | "12345" | "123456" (typed union from resolver)
```

---

### `withInstanceKeys(provider, instanceKeys, resolver)`

A utility for creating typed provider definitions with explicit instance keys. This enables better TypeScript support when working with dynamic instance resolution.

```ts
import { withInstanceKeys } from '@sasha-milenkovic/h3-oauth-kit';

// Define possible instance keys and resolution logic
const clioProvider = withInstanceKeys(
  'clio',
  ['smithlaw', 'johnsonlegal', 'LOAG'],
  (event) => {
    const { firmId } = getRouterParams(event);
    return firmId; // TypeScript knows this must be one of the defined keys
  },
);

// Use in defineProtectedRoute
export default defineProtectedRoute([clioProvider], async (event) => {
  // TypeScript knows about all possible instance keys
  const instanceKey = event.context.h3OAuthKitInstances.clio; // 'smithlaw' | 'johnsonlegal' | 'LOAG'
  const tokens = event.context.h3OAuthKit[`clio:${instanceKey}`]; // Fully typed
});
```

---

### `handleOAuthLogout(providers, options?, event?)`

- Clears secure HTTP-only cookies for one or more providers.
- Can be used as a route handler or as a utility in a custom H3 route.
- **Supports both global and scoped (multi-tenant) providers**.
- Optionally redirects the user after logout, or returns a structured result.

#### Global Providers:

```ts
// server/api/auth/logout.get.ts
import { handleOAuthLogout } from '@sasha-milenkovic/h3-oauth-kit';

export default handleOAuthLogout(['azure', 'clio'], {
  redirectTo: '/login',
});
```

#### Scoped Providers (Multi-Tenant):

```ts
// Logout specific tenant/instance combinations
export default handleOAuthLogout(
  [
    { provider: 'azure', instanceKey: 'tenant-a' },
    { provider: 'clio', instanceKey: 'smithlaw' },
  ],
  {
    redirectTo: '/login',
  },
);
```

#### Mixed Global and Scoped:

```ts
// Logout global azure + scoped clio
export default handleOAuthLogout(
  [
    'azure', // Global
    { provider: 'clio', instanceKey: 'smithlaw' }, // Scoped
  ],
  {
    redirectTo: '/login',
  },
);
```

#### Utility Usage (e.g., inside a custom route handler)

```ts
import { defineEventHandler } from 'h3';
import { handleOAuthLogout } from '@sasha-milenkovic/h3-oauth-kit';

export default defineEventHandler(async (event) => {
  const result = await handleOAuthLogout(['azure'], {}, event);

  return {
    message: 'User logged out',
    ...result,
  };
});
```

### Dynamic Usage (providers via query param)

```ts
// server/api/auth/logout.get.ts
import { defineEventHandler, getQuery } from 'h3';
import { handleOAuthLogout } from '@sasha-milenkovic/h3-oauth-kit';

export default defineEventHandler((event) => {
  const { providers } = getQuery(event);

  const providersArray = Array.isArray(providers)
    ? providers
    : [providers].filter(Boolean);

  if (!providersArray.length) {
    throw createError({
      statusCode: 400,
      statusMessage: "Missing or invalid 'providers' query parameter",
    });
  }

  return handleOAuthLogout(providersArray, { redirectTo: '/login' }, event);
});
```

💡 Supports query strings like:
/api/auth/logout?providers=azure&providers=clio

---

## Multi-Tenant Key Format

When using scoped providers (multi-tenant), the keys follow a specific format:

### Context Access Patterns

```ts
// Tokens - Global providers use dot notation
event.context.h3OAuthKit.azure.access_token;
event.context.h3OAuthKit.clio.access_token;

// Tokens - Scoped providers use bracket notation (because of the colon)
event.context.h3OAuthKit['azure:tenant-a'].access_token;
event.context.h3OAuthKit['clio:smithlaw'].access_token;
event.context.h3OAuthKit['intuit:company-123'].access_token;

// Instance Keys - Access resolved instance keys (helpful for dynamic resolution)
event.context.h3OAuthKitInstances.azure; // undefined | string
event.context.h3OAuthKitInstances.clio; // undefined | string (typed when using withInstanceKeys)
event.context.h3OAuthKitInstances.intuit; // undefined | string
```

### Cookie Names

Cookies follow the same pattern:

```ts
// Global providers
azure_access_token
clio_refresh_token

// Scoped providers
azure:tenant-a_access_token
clio:smithlaw_refresh_token
intuit:company-123_access_token_expires_at
```

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

Made with ❤️ by [@sasha-milenkovic](https://github.com/sashamilenkovic)
