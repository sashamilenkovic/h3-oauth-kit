import { defineEventHandler, createError, sendRedirect, setCookie, getQuery, getCookie, deleteCookie } from 'h3';
import { ofetch } from 'ofetch';

function defineProtectedRoute(providers, handler) {
  return defineEventHandler((event) => {
    for (const provider of providers) {
      const key = `${provider}AccessToken`;
      if (!event.context[key]) {
        throw createError({
          statusCode: 401,
          message: `Missing ${provider} access token`
        });
      }
    }
    return handler(
      event
    );
  });
}

const providerRegistry = /* @__PURE__ */ new Map();
function defineOAuthProvider(provider, config) {
  providerRegistry.set(provider, config);
}
function getOAuthProviderConfig(provider) {
  const config = providerRegistry.get(provider);
  if (!config) {
    throw new Error(`OAuth provider "${provider}" is not registered.`);
  }
  return config;
}

function buildAuthUrl({
  authorizeEndpoint,
  clientId,
  redirectUri,
  scopes,
  state
}) {
  const url = new URL(authorizeEndpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  return url.toString();
}
function resolveState(event, provider, userState) {
  const state = typeof userState === "function" ? userState(event) : userState || crypto.randomUUID();
  setCookie(event, `${provider}_oauth_state`, state, {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: true,
    maxAge: 300
  });
  return state;
}
function handleOAuthLogin(provider, options) {
  return defineEventHandler((event) => {
    const config = getOAuthProviderConfig(provider);
    const state = resolveState(event, provider, options?.state);
    const authUrl = buildAuthUrl({
      authorizeEndpoint: config.authorizeEndpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes: config.scopes,
      state
    });
    if (options?.mode === "manual") {
      return { url: authUrl };
    }
    return sendRedirect(event, authUrl, 302);
  });
}

async function exchangeCodeForTokens(input) {
  const params = {
    client_id: input.clientId,
    client_secret: input.clientSecret,
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri
  };
  if (input.scope) {
    params.scope = input.scope;
  }
  try {
    return await ofetch(input.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams(params).toString()
    });
  } catch (error) {
    console.error("OAuth token exchange failed:", error);
    throw createError({ statusCode: 500, message: "Token exchange failed" });
  }
}
function setTokenCookies(event, tokens, provider) {
  const base = {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/"
  };
  console.log("tokens", tokens);
  if (tokens.access_token) {
    let cleaned = tokens.access_token.startsWith("Bearer ") ? tokens.access_token.slice(7) : tokens.access_token;
    setCookie(event, `${provider}_access_token`, cleaned, {
      ...base,
      maxAge: tokens.expires_in
    });
    const expiry = Math.floor(Date.now() / 1e3) + (tokens.expires_in ?? 3600);
    setCookie(event, `${provider}_token_expiry`, expiry.toString(), base);
  }
  if (tokens.refresh_token) {
    setCookie(event, `${provider}_refresh_token`, tokens.refresh_token, {
      ...base,
      maxAge: 30 * 24 * 60 * 60
      // 30 days
    });
  }
  if (tokens.ext_expires_in) {
    setCookie(
      event,
      `${provider}_ext_expires_in`,
      tokens.ext_expires_in.toString(),
      base
    );
  }
  if (tokens.x_refresh_token_expires_in) {
    setCookie(
      event,
      `${provider}_x_refresh_token_expires_in`,
      tokens.x_refresh_token_expires_in.toString(),
      base
    );
  }
  if (tokens.clio_client_id) {
    setCookie(event, `clio_client_id`, tokens.clio_client_id, base);
  }
  if (tokens.intuit_client_id) {
    setCookie(event, `intuit_client_id`, tokens.intuit_client_id, base);
  }
}
function verifyStateParam(event, provider) {
  const query = getQuery(event);
  const expectedState = getCookie(event, `${provider}_oauth_state`);
  const actualState = query.state;
  if (!expectedState || typeof actualState !== "string") {
    throw createError({
      statusCode: 400,
      statusMessage: `Missing or invalid state for ${provider} OAuth callback`
    });
  }
  if (actualState !== expectedState) {
    throw createError({
      statusCode: 401,
      statusMessage: `State mismatch for ${provider} OAuth callback`
    });
  }
  deleteCookie(event, `${provider}_oauth_state`);
}

function handleOAuthCallback(provider, options) {
  return defineEventHandler(async (event) => {
    const query = getQuery(event);
    const code = query.code;
    if (!code || typeof code !== "string") {
      throw createError({
        statusCode: 400,
        statusMessage: "Authorization code missing in callback URL"
      });
    }
    verifyStateParam(event, provider);
    const config = getOAuthProviderConfig(provider);
    const tokenResponse = await exchangeCodeForTokens({
      code,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      redirectUri: config.redirectUri,
      tokenEndpoint: config.tokenEndpoint,
      scope: config.scopes?.join(" ")
    });
    setTokenCookies(event, tokenResponse, provider);
    return sendRedirect(event, options?.redirectTo || "/", 302);
  });
}

export { defineOAuthProvider, defineProtectedRoute, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin };
