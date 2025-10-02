# Adding Custom OAuth Providers

Starting with `v0.12.0`, `h3-oauth-kit` supports custom OAuth providers through TypeScript module augmentation. This allows you to add support for any OAuth 2.0 provider (Google, GitHub, Facebook, etc.) while maintaining full type safety.

## Overview

The package comes with built-in support for:

- Azure
- Clio
- Intuit
- MyCase

For any other OAuth provider, you can add support by:

1. Creating a type augmentation file
2. Registering the provider with standard OAuth 2.0 endpoints

## Quick Example: Google OAuth

### Step 1: Create Type Augmentation File

Create a file `types/h3-oauth-kit.d.ts` in your project:

```typescript
import '@sasha-milenkovic/h3-oauth-kit';

declare module '@sasha-milenkovic/h3-oauth-kit' {
  // Extend CustomOAuthProviders to include Google
  interface CustomOAuthProviders {
    google: 'google';
  }

  // Define Google-specific token response
  interface GoogleAuthTokens {
    access_token: string;
    refresh_token?: string;
    expires_in: number;
    token_type: 'Bearer';
    scope?: string;
    id_token?: string;
  }

  // Define Google-specific provider config
  interface GoogleOAuthProviderConfig {
    clientId: string;
    clientSecret: string;
    authorizeEndpoint: string;
    tokenEndpoint: string;
    redirectUri: string;
    scopes: string[];
    encrypt: (text: string) => Promise<string>;
    decrypt: (encryptedText: string) => Promise<string>;
  }

  // Define Google-specific refresh token response
  interface GoogleRefreshTokenResponse {
    access_token: string;
    refresh_token?: string;
    token_type: 'Bearer';
    expires_in: number;
    scope?: string;
    id_token?: string;
  }

  // Extend the type maps
  interface CustomProviderTokenMap {
    google: GoogleAuthTokens;
  }

  interface CustomProviderConfigMap {
    google: GoogleOAuthProviderConfig;
  }

  interface CustomInputProviderConfigMap {
    google: Omit<GoogleOAuthProviderConfig, 'encrypt' | 'decrypt'>;
  }

  interface CustomRefreshTokenResponseMap {
    google: GoogleRefreshTokenResponse;
  }
}
```

### Step 2: Configure TypeScript

Ensure TypeScript includes your types file:

**Nuxt:**

```typescript
// nuxt.config.ts
export default defineNuxtConfig({
  typescript: {
    tsConfig: {
      include: ['types/**/*.d.ts'],
    },
  },
});
```

**Standard TypeScript:**

```json
// tsconfig.json
{
  "include": ["types/**/*.d.ts", "src/**/*"]
}
```

### Step 3: Register the Provider

```typescript
// server/plugins/oauthProviders.ts
import {
  useOAuthRegistry,
  hasOAuthProviderConfig,
} from '@sasha-milenkovic/h3-oauth-kit';

export default defineNitroPlugin((nitroApp) => {
  nitroApp.hooks.hook('request', () => {
    const config = useRuntimeConfig();
    const { registerOAuthProvider } = useOAuthRegistry(
      config.h3OAuthEncryptionKey,
    );

    if (!hasOAuthProviderConfig('google')) {
      registerOAuthProvider('google', {
        clientId: config.googleClientId,
        clientSecret: config.googleClientSecret,
        authorizeEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenEndpoint: 'https://oauth2.googleapis.com/token',
        redirectUri: config.googleRedirectUri,
        scopes: [
          'openid',
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
        ],
      });
    }
  });
});
```

### Step 4: Use the Provider

Now you can use Google just like any built-in provider - **no `as any` needed**:

```typescript
// Login
export default handleOAuthLogin('google');

// Callback
export default handleOAuthCallback('google', { redirectTo: '/' });

// Protected Route
export default defineProtectedRoute(['google'], async (event) => {
  // Full type safety!
  const token = event.context.h3OAuthKit.google.access_token;

  const user = await $fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${token}` },
  });

  return user;
});

// Logout
export default handleOAuthLogout(['google'], { redirectTo: '/login' });
```

## Adding Other Providers

The same pattern works for any OAuth 2.0 provider. Here are examples for other popular providers:

### GitHub

```typescript
declare module '@sasha-milenkovic/h3-oauth-kit' {
  interface CustomOAuthProviders {
    github: 'github';
  }

  interface GitHubAuthTokens {
    access_token: string;
    token_type: 'bearer';
    scope: string;
    expires_in?: number;
    refresh_token?: string;
  }

  interface CustomProviderTokenMap {
    github: GitHubAuthTokens;
  }

  // ... other type maps
}

// Register
registerOAuthProvider('github', {
  clientId: 'YOUR_GITHUB_CLIENT_ID',
  clientSecret: 'YOUR_GITHUB_CLIENT_SECRET',
  authorizeEndpoint: 'https://github.com/login/oauth/authorize',
  tokenEndpoint: 'https://github.com/login/oauth/access_token',
  redirectUri: 'http://localhost:3000/api/auth/github/callback',
  scopes: ['user:email'],
});
```

### Facebook

```typescript
declare module '@sasha-milenkovic/h3-oauth-kit' {
  interface CustomOAuthProviders {
    facebook: 'facebook';
  }

  interface FacebookAuthTokens {
    access_token: string;
    token_type: 'bearer';
    expires_in: number;
  }

  interface CustomProviderTokenMap {
    facebook: FacebookAuthTokens;
  }

  // ... other type maps
}

// Register
registerOAuthProvider('facebook', {
  clientId: 'YOUR_FACEBOOK_APP_ID',
  clientSecret: 'YOUR_FACEBOOK_APP_SECRET',
  authorizeEndpoint: 'https://www.facebook.com/v18.0/dialog/oauth',
  tokenEndpoint: 'https://graph.facebook.com/v18.0/oauth/access_token',
  redirectUri: 'http://localhost:3000/api/auth/facebook/callback',
  scopes: ['email', 'public_profile'],
});
```

## Type System Details

The package uses conditional types and module augmentation to provide:

1. **Full IntelliSense**: Auto-completion for provider names and token properties
2. **Type Safety**: Compile-time errors for invalid provider usage
3. **Extensibility**: Add custom providers without modifying the package
4. **Backward Compatibility**: Existing code continues to work

### How It Works

The type system uses these extensible interfaces:

```typescript
// Declare your custom provider
interface CustomOAuthProviders {
  myProvider: 'myProvider';
}

// Define its token structure
interface CustomProviderTokenMap {
  myProvider: MyProviderTokens;
}

// Define its configuration
interface CustomProviderConfigMap {
  myProvider: MyProviderConfig;
}
```

The package automatically merges these with built-in providers, giving you a unified type-safe API.

## Default Behavior

If you register a provider without type augmentation, it will use generic types:

```typescript
// Without type augmentation
registerOAuthProvider('generic-provider' as any, {
  /* config */
});

// Generic types will be used:
// - GenericAuthTokens (with access_token, refresh_token, expires_in)
// - GenericOAuthProviderConfig
// - GenericRefreshTokenResponse
```

This works, but you lose specific type information. Type augmentation is highly recommended for better developer experience.

## Provider-Specific Features

### Custom Cookie Fields

If your provider returns additional fields that should be stored in cookies, define them in your token type:

```typescript
interface MyProviderAuthTokens {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: 'Bearer';
  custom_field: string; // This will be automatically stored
}
```

### Refresh Token Handling

The package automatically handles refresh token logic. If your provider has special refresh requirements:

```typescript
interface MyProviderRefreshTokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: 'Bearer';
  // Any additional fields your provider returns
}
```

### Callback Query Parameters

Some providers return additional data in the callback URL:

```typescript
interface MyProviderOAuthCallbackQuery {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
  custom_param?: string; // Provider-specific parameter
}

interface CustomCallbackQueryMap {
  myProvider: MyProviderOAuthCallbackQuery;
}
```

## Multi-Tenant Support

Custom providers work seamlessly with multi-tenant configurations:

```typescript
// Register multiple Google instances
registerOAuthProvider('google', 'tenant-a', {
  /* config */
});
registerOAuthProvider('google', 'tenant-b', {
  /* config */
});

// Use in protected routes
defineProtectedRoute(
  [{ provider: 'google', instanceKey: 'tenant-a' }],
  async (event) => {
    const tokens = event.context.h3OAuthKit['google:tenant-a'];
  },
);
```

## Best Practices

1. **Create a dedicated types directory**: Keep type augmentations organized
2. **One file per provider**: Easier to maintain and understand
3. **Document token fields**: Add JSDoc comments explaining each field
4. **Test token refresh**: Ensure your refresh token response type matches reality
5. **Handle errors gracefully**: Different providers have different error formats

## Troubleshooting

### Types not recognized

Ensure your `tsconfig.json` includes the types directory:

```json
{
  "include": ["types/**/*.d.ts"]
}
```

### Still seeing `as any` errors

Make sure you:

1. Imported the package in your type file: `import '@sasha-milenkovic/h3-oauth-kit';`
2. Used `declare module` to augment the module
3. Restarted your TypeScript server

### Provider registration fails

Check that:

1. All required config fields are provided
2. Endpoints are valid URLs
3. Scopes are in the correct format for your provider

## Examples

See the `examples/` directory for complete working examples:

- Google OAuth integration
- GitHub OAuth integration
- Multi-provider setup

## Contributing

Found a popular provider that should be built-in? Open a PR with:

1. Provider configuration in `src/providerConfig.ts`
2. Type definitions in `src/types.ts`
3. Tests in `tests/`
4. Documentation

## Questions?

Open an issue on GitHub with the `custom-provider` label.
