# h3-oauth-kit

[![codecov](https://codecov.io/github/sashamilenkovic/h3-oauth-kit/graph/badge.svg?token=Y4JAJQWYCQ)](https://codecov.io/github/sashamilenkovic/h3-oauth-kit)
![Run Vitest](https://github.com/sashamilenkovic/h3-oauth-kit/actions/workflows/ci.yml/badge.svg)

A **cookie-based**, type-safe OAuth 2.0 toolkit for [H3](https://github.com/unjs/h3) apps.
Handles login, callback, token refresh, and protected route middleware — all with automatic HTTP-only cookie storage and typed provider extensions.

> **Built-in providers:** `azure`, `clio`, `intuit`, `mycase`  
> **Custom providers:** Add support for any OAuth 2.0 provider (Google, GitHub, Facebook, etc.) with full type safety via module augmentation.  
> See [CUSTOM_PROVIDERS.md](./CUSTOM_PROVIDERS.md) for details.

---

## Philosophy

**h3-oauth-kit is designed around HTTP-only cookies** for token storage. This approach:

- ✅ **Serverless-friendly** — No Redis, database, or external dependencies required
- ✅ **Secure by default** — HTTP-only cookies prevent XSS attacks; refresh tokens are AES-256 encrypted
- ✅ **Simple architecture** — Works out of the box with zero infrastructure setup
- ✅ **Fast** — No network calls to retrieve tokens from external storage
- ✅ **Multi-tenant ready** — Instance keys enable per-tenant OAuth configurations

### When h3-oauth-kit Might Not Be the Right Fit

This library stores OAuth tokens in HTTP-only cookies. If your use case requires:

- ❌ Centralized token storage (Redis/database-backed sessions)
- ❌ Tokens must never touch client devices (even encrypted)
- ❌ Immediate token revocation across all devices/instances
- ❌ Cross-device session sharing (one login, multiple devices)
- ❌ Tokens larger than 4KB (browser cookie size limits)

...you may need a different solution or should implement OAuth with custom session management.

For the vast majority of H3/Nuxt applications, cookie-based storage is the ideal balance of security, simplicity, and performance.

---

## Features

- 🔐 OAuth 2.0 Authorization Code flow support
- 🤖 **NEW:** Client Credentials flow for machine-to-machine auth
- 🔍 **NEW:** Token Introspection (RFC 7662) - validate token status
- 📱 **NEW:** Device Authorization Flow (RFC 8628) - for CLI tools & IoT
- 🔒 **NEW:** JWT Validation (RFC 7519) - decode, validate, verify signatures
- 🍪 Secure HTTP-only cookie storage (AES-256 encrypted refresh tokens)
- 🔁 Automatic token refresh on protected routes
- 🧠 State validation & metadata preservation
- 🛠️ Utility-first API with full TypeScript safety
- 🎨 Extensible type system for custom OAuth providers
- 🏢 Multi-tenant / multi-instance support
- ⚡ In-memory caching (client credentials tokens + JWKS keys)
- 🌲 **Tree-shakable** - import only what you need

---

## Tree-Shakable Imports

**v1.1.0+** introduces tree-shakable subpath exports for optimal bundle size.

### Why Tree-Shaking Matters

Each optional feature (introspection, device flow) adds ~2-3KB to your bundle. With subpath exports, you only include what you use:

```typescript
// ❌ Imports everything (even if you don't use introspection/device flow)
import { handleOAuthLogin, introspectToken } from '@milencode/h3-oauth-kit';

// ✅ Tree-shakable: only imports introspection (~2KB)
import { introspectToken } from '@milencode/h3-oauth-kit/introspection';

// ✅ Tree-shakable: only imports device flow (~3KB)
import { initiateDeviceFlow } from '@milencode/h3-oauth-kit/device-flow';
```

### Available Subpaths

| Subpath | What it includes | When to use |
|---------|------------------|-------------|
| `@milencode/h3-oauth-kit` | Core OAuth (login, callback, refresh, protected routes) | **Always** - this is the main package |
| `@milencode/h3-oauth-kit/introspection` | Token introspection (RFC 7662) | When you need to validate tokens with the provider |
| `@milencode/h3-oauth-kit/device-flow` | Device authorization (RFC 8628) | For CLI tools, TV apps, IoT devices |
| `@milencode/h3-oauth-kit/jwt` | JWT validation (RFC 7519) | When you need to decode/validate JWTs locally |

### Example: Keeping Your Bundle Lean

```typescript
// server/routes/auth/login.post.ts
import { handleOAuthLogin } from '@milencode/h3-oauth-kit';

export default defineEventHandler((event) => 
  handleOAuthLogin('azure', {}, event)
);
```

```typescript
// server/routes/admin/validate-token.ts
// Only imported in this route - not included in other routes' bundles
import { introspectToken } from '@milencode/h3-oauth-kit/introspection';

export default defineEventHandler(async (event) => {
  const token = getHeader(event, 'authorization')?.split(' ')[1];
  const isValid = await introspectToken('azure', token);
  return { valid: isValid };
});
```

```typescript
// cli-tool.ts - No web dependencies needed
import { authenticateDevice } from '@milencode/h3-oauth-kit/device-flow';

const tokens = await authenticateDevice('github', {
  scopes: ['repo', 'user'],
  onStart: (auth) => {
    console.log(`Visit: ${auth.verification_uri}`);
    console.log(`Code: ${auth.user_code}`);
  },
});
```

**Result:** Your H3 API routes stay lean - introspection code only loads when that route is called!

---

## Installation

```bash
npm install @milencode/h3-oauth-kit
```

Or using yarn:

```bash
yarn add @milencode/h3-oauth-kit
```

Or using pnpm:

```bash
pnpm add @milencode/h3-oauth-kit
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
declare module '@milencode/h3-oauth-kit' {
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
import { registerOAuthProvider } from '@milencode/h3-oauth-kit';

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
import { handleOAuthLogin } from '@milencode/h3-oauth-kit';

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
import { handleOAuthCallback } from '@milencode/h3-oauth-kit';

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
import { defineProtectedRoute } from '@milencode/h3-oauth-kit';

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
import { defineProtectedRoute } from '@milencode/h3-oauth-kit';

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
} from '@milencode/h3-oauth-kit';
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
import { withInstanceKeys } from '@milencode/h3-oauth-kit';

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
import { handleOAuthLogout } from '@milencode/h3-oauth-kit';

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
import { handleOAuthLogout } from '@milencode/h3-oauth-kit';

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
import { handleOAuthLogout } from '@milencode/h3-oauth-kit';

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

### `getClientCredentialsToken(provider, options?)`

**NEW!** Retrieves an access token using the OAuth 2.0 Client Credentials flow (RFC 6749 Section 4.4).

This is for **machine-to-machine authentication** where no user is involved. Perfect for:
- Backend services calling APIs
- Scheduled jobs/cron tasks
- CI/CD pipelines
- Microservices authentication

#### Features:
- ✅ **Automatic caching**: Tokens are cached in memory until they expire
- ✅ **Multi-tenant support**: Works with scoped provider configurations
- ✅ **Custom scopes**: Override default scopes per request
- ✅ **Zero user interaction**: Pure service-to-service auth

#### Basic Usage:

```ts
import { getClientCredentialsToken } from '@milencode/h3-oauth-kit';

// Get a token for calling Microsoft Graph API
const token = await getClientCredentialsToken('azure', {
  scopes: ['https://graph.microsoft.com/.default'],
});

// Use the token to make API calls
const users = await $fetch('https://graph.microsoft.com/v1.0/users', {
  headers: {
    Authorization: `Bearer ${token.access_token}`,
  },
});
```

#### Multi-Tenant Example:

```ts
// Different tokens for different tenants
const tenantAToken = await getClientCredentialsToken('azure', {
  instanceKey: 'tenant-a',
  scopes: ['api://myapp/.default'],
});

const tenantBToken = await getClientCredentialsToken('azure', {
  instanceKey: 'tenant-b',
  scopes: ['api://myapp/.default'],
});
```

#### Background Job Example:

```ts
// server/cron/syncAccounting.ts
import { getClientCredentialsToken } from '@milencode/h3-oauth-kit';

export async function syncAccountingData() {
  // Get token without any user context
  const token = await getClientCredentialsToken('intuit', {
    scopes: ['com.intuit.quickbooks.accounting'],
  });

  // Fetch invoices from QuickBooks
  const invoices = await $fetch(
    'https://quickbooks.api.intuit.com/v3/company/123/query?query=select * from Invoice',
    {
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        Accept: 'application/json',
      },
    },
  );

  // Process invoices...
  return { synced: invoices.length };
}
```

#### Options:

```ts
interface ClientCredentialsOptions {
  /** OAuth scopes to request. Overrides provider's default scopes */
  scopes?: string[];
  /** Force a new token even if cached token is valid */
  forceRefresh?: boolean;
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
}
```

#### Cache Management:

```ts
import {
  clearClientCredentialsCache,
  getClientCredentialsCacheSize,
} from '@milencode/h3-oauth-kit';

// Clear all cached tokens
clearClientCredentialsCache();

// Clear tokens for specific provider
clearClientCredentialsCache('azure');

// Clear tokens for specific provider instance
clearClientCredentialsCache('azure', 'tenant-a');

// Check cache size (useful for monitoring)
const size = getClientCredentialsCacheSize();
console.log(`Cached tokens: ${size}`);
```

#### How Caching Works:

Tokens are cached in memory based on:
1. Provider name (e.g., `azure`)
2. Instance key (if multi-tenant)
3. Requested scopes

This means different scope combinations get separate cache entries, ensuring you always get the right token for your use case.

Tokens are automatically refreshed when they expire (with a 60-second buffer to prevent edge cases).

#### When to Use Client Credentials vs Authorization Code:

| Use Client Credentials when... | Use Authorization Code when... |
|--------------------------------|--------------------------------|
| ✅ Backend service calling APIs | ✅ User needs to login |
| ✅ Scheduled jobs/cron tasks | ✅ Accessing user-specific data |
| ✅ No user context needed | ✅ OAuth requires user consent |
| ✅ M2M (machine-to-machine) auth | ✅ User session management |

---

### `introspectToken(provider, token, options?)` 🌲

**NEW!** Validates a token with the OAuth provider using Token Introspection (RFC 7662).

**Tree-shakable:** Import from `@milencode/h3-oauth-kit/introspection`

Token introspection allows you to check if an access token or refresh token is still active, hasn't been revoked, and retrieve metadata about the token.

#### Use Cases:
- **Security-critical applications**: Verify tokens haven't been revoked
- **Token validation**: Check token status before making API calls
- **Audit logging**: Get token metadata for compliance
- **Token debugging**: Inspect token details during development

#### Basic Usage:

```typescript
import { introspectToken } from '@milencode/h3-oauth-kit/introspection';

const result = await introspectToken('azure', 'access_token_here');

if (result.active) {
  console.log('Token is valid!');
  console.log('Expires at:', new Date(result.exp! * 1000));
  console.log('Scopes:', result.scope);
} else {
  console.log('Token is invalid or revoked');
}
```

#### In a Protected Route:

```typescript
import { defineProtectedRoute } from '@milencode/h3-oauth-kit';
import { introspectToken } from '@milencode/h3-oauth-kit/introspection';

export default defineProtectedRoute(['azure'], async (event) => {
  const token = event.context.h3OAuthKit.azure.access_token;

  // Double-check token is still active (e.g., not revoked by admin)
  const introspection = await introspectToken('azure', token);

  if (!introspection.active) {
    throw createError({
      statusCode: 401,
      message: 'Token has been revoked',
    });
  }

  // Proceed with API call...
  return { status: 'authorized', scopes: introspection.scope };
});
```

#### Options:

```typescript
interface IntrospectionOptions {
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
  /** Hint about the type of token being introspected */
  tokenTypeHint?: 'access_token' | 'refresh_token';
}

// With type hint (optimization for provider)
const result = await introspectToken('clio', refreshToken, {
  tokenTypeHint: 'refresh_token',
});

// Multi-tenant
const result = await introspectToken('azure', token, {
  instanceKey: 'tenant-a',
});
```

#### Response Format (RFC 7662):

```typescript
interface TokenIntrospectionResponse {
  /** REQUIRED - Boolean indicator of whether or not the token is currently active */
  active: boolean;
  /** OAuth 2.0 scope values for this token */
  scope?: string;
  /** Client identifier for the OAuth 2.0 client that requested this token */
  client_id?: string;
  /** Human-readable identifier for the resource owner */
  username?: string;
  /** Type of the token (e.g., "Bearer") */
  token_type?: string;
  /** Timestamp when token expires (seconds since epoch) */
  exp?: number;
  /** Timestamp when token was issued (seconds since epoch) */
  iat?: number;
  /** Subject of the token */
  sub?: string;
  /** Intended audience */
  aud?: string | string[];
  // ... additional provider-specific fields
}
```

#### Helper Function: `isTokenActive`

```typescript
import { isTokenActive } from '@milencode/h3-oauth-kit/introspection';

// Simplified check - just returns true/false
const isValid = await isTokenActive('azure', accessToken);
if (isValid) {
  // Token is good to use
}
```

#### Important Notes:

- Not all OAuth providers support introspection (requires RFC 7662 support)
- Provider must have `introspectionEndpoint` configured:
  ```typescript
  registerOAuthProvider('azure', {
    // ... other config
    introspectionEndpoint: 'https://provider.com/oauth2/v2.0/introspect',
  });
  ```

---

### Device Authorization Flow 🌲

**NEW!** Authenticate devices without a web browser using Device Authorization Flow (RFC 8628).

**Tree-shakable:** Import from `@milencode/h3-oauth-kit/device-flow`

The Device Authorization Flow is designed for devices that lack a web browser or have limited input capabilities (TVs, CLI tools, IoT devices, etc.).

#### How it Works:

1. Device calls `initiateDeviceFlow()` → receives `user_code` and `verification_uri`
2. Device displays these to the user
3. User opens the URL on another device (phone/computer) and enters the code
4. Device polls for token using `pollForDeviceToken()`

#### Use Cases:

- **CLI tools**: Authenticate users from terminal
- **Smart TVs**: Login flow for streaming apps  
- **IoT devices**: Devices without browsers
- **CI/CD pipelines**: Authenticate build processes

---

#### `initiateDeviceFlow(provider, options?)`

Starts the device authorization flow.

```typescript
import { initiateDeviceFlow, pollForDeviceToken } from '@milencode/h3-oauth-kit/device-flow';

const deviceAuth = await initiateDeviceFlow('azure', {
  scopes: ['User.Read', 'Mail.Send'],
});

console.log('Please visit:', deviceAuth.verification_uri);
console.log('And enter code:', deviceAuth.user_code);
```

**Response:**

```typescript
interface DeviceAuthorizationResponse {
  /** The device verification code */
  device_code: string;
  /** The end-user verification code (show to user) */
  user_code: string;
  /** The verification URL on the authorization server */
  verification_uri: string;
  /** Optional: URL that includes the user_code for easier UX */
  verification_uri_complete?: string;
  /** Lifetime in seconds of the codes */
  expires_in: number;
  /** Minimum polling interval in seconds */
  interval?: number;
}
```

---

#### `pollForDeviceToken(provider, deviceCode, options?)`

Waits for the user to authorize the device and returns tokens.

```typescript
// After showing the user code
const tokens = await pollForDeviceToken('azure', deviceAuth.device_code, {
  maxWaitTime: 300, // Wait up to 5 minutes
  pollInterval: 5,  // Poll every 5 seconds
  onPoll: (attempt, secondsElapsed) => {
    console.log(`Waiting for authorization... (${secondsElapsed}s elapsed)`);
  },
});

console.log('Success! Access token:', tokens.access_token);
```

**Options:**

```typescript
interface DeviceTokenPollOptions {
  /** Maximum time to wait in seconds (default: 300 = 5 minutes) */
  maxWaitTime?: number;
  /** Custom polling interval in seconds */
  pollInterval?: number;
  /** Instance key for multi-tenant configurations */
  instanceKey?: string;
  /** Callback invoked on each poll attempt */
  onPoll?: (attempt: number, secondsElapsed: number) => void | Promise<void>;
}
```

**Error Handling:**

- Throws `"User denied authorization"` if user denies access
- Throws `"Device code expired"` if codes expire before authorization
- Throws `"timed out after N seconds"` if maxWaitTime is reached
- Automatically handles `slow_down` errors by increasing poll interval

---

#### `authenticateDevice(provider, options?)`

Convenience function that combines `initiateDeviceFlow` and `pollForDeviceToken`.

**Perfect for CLI tools:**

```typescript
import { authenticateDevice } from '@milencode/h3-oauth-kit/device-flow';

const tokens = await authenticateDevice('github', {
  scopes: ['repo', 'user'],
  onStart: (deviceAuth) => {
    console.log('Visit:', deviceAuth.verification_uri);
    console.log('Code:', deviceAuth.user_code);
  },
  onPoll: (attempt, seconds) => {
    console.log(`Waiting... (${seconds}s)`);
  },
});

console.log('Authenticated!', tokens.access_token);
```

#### QR Code Example:

```typescript
import QRCode from 'qrcode';
import { authenticateDevice } from '@milencode/h3-oauth-kit/device-flow';

const tokens = await authenticateDevice('azure', {
  onStart: async (auth) => {
    // Generate QR code for mobile scanning
    const qr = await QRCode.toString(
      auth.verification_uri_complete || auth.verification_uri,
      { type: 'terminal' }
    );
    
    console.log(qr);
    console.log('\nOr manually visit:', auth.verification_uri);
    console.log('And enter code:', auth.user_code);
  },
});
```

#### Configuration:

Provider must have `deviceAuthorizationEndpoint` configured:

```typescript
registerOAuthProvider('azure', {
  // ... other config
  deviceAuthorizationEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/devicecode',
  tokenEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
});
```

---

### JWT Validation 🌲

**NEW!** Decode and validate JWT tokens locally without API calls (RFC 7519).

**Tree-shakable:** Import from `@milencode/h3-oauth-kit/jwt`

JWT validation lets you verify tokens locally, validate claims, and optionally verify signatures using JWKS. This is significantly faster than token introspection since it doesn't require network calls.

#### Why JWT Validation?

- ⚡ **Fast** - No network calls needed for validation
- 🔒 **Secure** - Verify signatures with public keys (JWKS)
- 📦 **Offline-capable** - Works without internet access
- 🎯 **Flexible** - Validate specific claims (iss, aud, exp, etc.)

---

#### `decodeJWT(token)` 

Decodes a JWT without any validation.

**⚠️ Warning:** This does NOT validate the token! Use `validateJWT()` for secure validation.

```typescript
import { decodeJWT } from '@milencode/h3-oauth-kit/jwt';

const decoded = decodeJWT(token);
console.log('User ID:', decoded.payload.sub);
console.log('Expires:', new Date(decoded.payload.exp! * 1000));
console.log('Algorithm:', decoded.header.alg);
```

**Returns:**
```typescript
interface DecodedJWT {
  header: {
    alg: string;      // e.g., "RS256"
    typ?: string;     // e.g., "JWT"
    kid?: string;     // Key ID
  };
  payload: {
    sub?: string;     // Subject
    iss?: string;     // Issuer
    aud?: string | string[];  // Audience
    exp?: number;     // Expiration (seconds since epoch)
    iat?: number;     // Issued at
    nbf?: number;     // Not before
    [key: string]: unknown;  // Custom claims
  };
  signature: string;
}
```

---

#### `getJWTPayload(token)`

Convenience function that returns only the payload.

```typescript
import { getJWTPayload } from '@milencode/h3-oauth-kit/jwt';

const payload = getJWTPayload(token);
console.log('User:', payload.sub);
console.log('Email:', payload.email);
```

---

#### `validateJWT(token, options?)`

Validates a JWT with comprehensive checks.

**Features:**
- ✅ Claims validation (exp, nbf, iat, iss, aud, sub)
- ✅ Signature verification (using JWKS)
- ✅ Clock tolerance for time-based checks
- ✅ Custom validation logic
- ✅ JWKS caching for performance

**Basic Usage:**

```typescript
import { validateJWT } from '@milencode/h3-oauth-kit/jwt';

const result = await validateJWT(token, {
  issuer: 'https://login.microsoftonline.com',
  audience: 'api://myapp',
});

if (result.valid) {
  console.log('Valid token!', result.payload);
} else {
  console.error('Invalid:', result.error);
  console.error('Code:', result.errorCode); // EXPIRED, INVALID_ISSUER, etc.
}
```

**With Signature Verification:**

```typescript
const result = await validateJWT(token, {
  issuer: 'https://accounts.google.com',
  audience: 'my-client-id',
  validateSignature: true,
  jwksUri: 'https://www.googleapis.com/oauth2/v3/certs',
});
```

**Validation Options:**

```typescript
interface JWTValidationOptions {
  /** Expected issuer (iss claim) */
  issuer?: string | string[];
  /** Expected audience (aud claim) */
  audience?: string | string[];
  /** Expected subject (sub claim) */
  subject?: string;
  /** Clock tolerance in seconds (default: 0) */
  clockTolerance?: number;
  /** Validate signature (default: true if jwksUri provided) */
  validateSignature?: boolean;
  /** JWKS URI for public keys */
  jwksUri?: string;
  /** Allowed signing algorithms (default: ['RS256', 'ES256', ...]) */
  algorithms?: string[];
  /** Maximum token age in seconds */
  maxTokenAge?: number;
  /** Custom validation function */
  customValidation?: (payload) => void | Promise<void>;
}
```

**In a Protected API Route:**

```typescript
import { defineEventHandler, getHeader, createError } from 'h3';
import { validateJWT } from '@milencode/h3-oauth-kit/jwt';

export default defineEventHandler(async (event) => {
  const authHeader = getHeader(event, 'authorization');
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    throw createError({ statusCode: 401, message: 'No token provided' });
  }
  
  const result = await validateJWT(token, {
    issuer: 'https://login.microsoftonline.com',
    audience: 'api://myapp',
    clockTolerance: 60, // 1 minute tolerance for clock skew
    jwksUri: 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
    validateSignature: true,
  });
  
  if (!result.valid) {
    throw createError({
      statusCode: 401,
      message: `Invalid token: ${result.error}`,
    });
  }
  
  // Token is valid - use the payload
  const userId = result.payload!.sub;
  const email = result.payload!.email;
  
  return { userId, email };
});
```

**Custom Validation:**

```typescript
const result = await validateJWT(token, {
  issuer: 'https://provider.com',
  customValidation: (payload) => {
    // Require admin role
    if (payload.role !== 'admin') {
      throw new Error('Admin role required');
    }
    
    // Check custom claim
    if (!payload.organization_verified) {
      throw new Error('Organization not verified');
    }
  },
});
```

**Validation Result:**

```typescript
interface JWTValidationResult {
  valid: boolean;
  payload?: JWTPayload;  // If valid
  error?: string;         // If invalid
  errorCode?: 'EXPIRED' | 'NOT_YET_VALID' | 'INVALID_SIGNATURE' 
    | 'INVALID_ISSUER' | 'INVALID_AUDIENCE' | 'INVALID_FORMAT'
    | 'CUSTOM_VALIDATION_FAILED';
}
```

**JWKS Cache Management:**

```typescript
import { clearJWKSCache, getJWKSCacheSize } from '@milencode/h3-oauth-kit/jwt';

// JWKS keys are cached for 1 hour by default

// Clear all cached JWKS
clearJWKSCache();

// Clear specific JWKS URI
clearJWKSCache('https://login.microsoftonline.com/common/discovery/v2.0/keys');

// Check cache size
console.log('Cached JWKS entries:', getJWKSCacheSize());
```

**Real-World Example: API Gateway:**

```typescript
// server/middleware/auth.ts
import { defineEventHandler, getHeader, createError } from 'h3';
import { validateJWT } from '@milencode/h3-oauth-kit/jwt';

export default defineEventHandler(async (event) => {
  // Skip auth for public routes
  if (event.path.startsWith('/api/public')) {
    return;
  }
  
  const token = getHeader(event, 'authorization')?.split(' ')[1];
  
  if (!token) {
    throw createError({ statusCode: 401, message: 'Unauthorized' });
  }
  
  const result = await validateJWT(token, {
    issuer: ['https://accounts.google.com', 'https://login.microsoftonline.com'],
    audience: 'api://myapp',
    clockTolerance: 60,
    validateSignature: true,
    jwksUri: 
      token.includes('google') 
        ? 'https://www.googleapis.com/oauth2/v3/certs'
        : 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
  });
  
  if (!result.valid) {
    throw createError({
      statusCode: 401,
      message: `Token validation failed: ${result.error}`,
    });
  }
  
  // Attach user info to context
  event.context.user = {
    id: result.payload!.sub,
    email: result.payload!.email,
    name: result.payload!.name,
  };
});
```

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
