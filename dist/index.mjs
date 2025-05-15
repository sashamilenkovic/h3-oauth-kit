import { getCookie, createError, setCookie, deleteCookie, getQuery, defineEventHandler, sendRedirect } from 'h3';
import { ofetch } from 'ofetch';

const providerConfig = {
  azure: {
    providerSpecificFields: [
      {
        key: "ext_expires_in",
        cookieName: "azure_ext_expires_at",
        setter: (value) => String(Math.floor(Date.now() / 1e3) + Number(value))
      }
    ],
    callbackQueryFields: ["session_state", "id_token"]
  },
  clio: {
    providerSpecificFields: []
  },
  intuit: {
    providerSpecificFields: [
      {
        key: "x_refresh_token_expires_in",
        cookieName: "intuit_refresh_token_expires_at",
        setter: (value) => String(Math.floor(Date.now() / 1e3) + Number(value))
      }
    ],
    callbackQueryFields: ["realmId"],
    validateRefreshTokenExpiry: true
  }
};

function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i])) return false;
    }
    return true;
  }
  const keysA = Object.keys(a);
  const keysB = Object.keys(b);
  if (keysA.length !== keysB.length) return false;
  for (const key of keysA) {
    if (!(key in b)) return false;
    if (!deepEqual(a[key], b[key])) return false;
  }
  return true;
}
function setProviderCookies(event, tokens, provider, options) {
  const base = {
    httpOnly: true,
    secure: true,
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/"
  };
  const cleanedAccessToken = tokens.access_token.startsWith("Bearer ") ? tokens.access_token.slice(7) : tokens.access_token;
  setCookie(event, `${provider}_access_token`, cleanedAccessToken, {
    ...base,
    maxAge: tokens.expires_in
  });
  const expiry = Math.floor(Date.now() / 1e3) + tokens.expires_in;
  setCookie(event, `${provider}_access_token_expires_at`, String(expiry), base);
  if (tokens.refresh_token) {
    setCookie(event, `${provider}_refresh_token`, tokens.refresh_token, {
      ...base,
      maxAge: 30 * 24 * 60 * 60
    });
  }
  setProviderCookieFields(event, tokens, provider, base);
  return tokens;
}
async function parseOAuthError(error) {
  let statusCode = 500;
  let message = "Token exchange failed";
  if (typeof error === "object" && error !== null && "response" in error) {
    const response = error.response;
    if (typeof response === "object" && response !== null && "status" in response && typeof response.status === "number") {
      statusCode = response.status;
    }
    if (typeof response === "object" && response !== null && "json" in response && typeof response.json === "function") {
      try {
        const json = await response.json();
        if (json.error_description || json.error) {
          message = json.error_description || json.error;
        }
      } catch {
      }
    }
  }
  return { statusCode, message };
}
function omitUndefinedValues(input) {
  return Object.fromEntries(
    Object.entries(input).filter(([_, v]) => v !== void 0)
  );
}
function parseOAuthState(rawState) {
  try {
    const parsed = JSON.parse(rawState);
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
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
  let stateValue;
  if (typeof userState === "function") {
    const result = userState(event);
    stateValue = typeof result === "string" ? result : JSON.stringify(result);
  } else if (typeof userState === "string") {
    stateValue = userState;
  } else if (typeof userState === "object" && userState !== null) {
    stateValue = JSON.stringify(userState);
  } else {
    stateValue = crypto.randomUUID();
  }
  setCookie(event, `${provider}_oauth_state`, stateValue, {
    httpOnly: true,
    path: "/",
    sameSite: "lax",
    secure: true,
    maxAge: 300
  });
  return stateValue;
}
function verifyStateParam(event, provider, state) {
  const cookieKey = `${provider}_oauth_state`;
  const expectedStateRaw = getCookie(event, cookieKey);
  if (!expectedStateRaw || typeof state !== "string") {
    throw createError({
      statusCode: 400,
      statusMessage: `Missing or invalid state for ${provider} OAuth callback`
    });
  }
  let parsedExpected = expectedStateRaw;
  let parsedReceived = state;
  try {
    parsedExpected = JSON.parse(expectedStateRaw);
    parsedReceived = JSON.parse(state);
  } catch {
  }
  const isMatch = typeof parsedExpected === "object" && typeof parsedReceived === "object" ? deepEqual(parsedExpected, parsedReceived) : parsedExpected === parsedReceived;
  if (!isMatch) {
    throw createError({
      statusCode: 401,
      statusMessage: `State mismatch for ${provider} OAuth callback`
    });
  }
  deleteCookie(event, cookieKey);
}
async function exchangeCodeForTokens(code, config, _provider) {
  const params = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri
  };
  if (config.scopes) {
    params.scope = config.scopes.join(" ");
  }
  try {
    return await ofetch(config.tokenEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams(params).toString()
    });
  } catch (error) {
    const { statusCode, message } = await parseOAuthError(error);
    throw createError({ statusCode, message });
  }
}
function parseOAuthCallbackQuery(event, provider) {
  const query = getQuery(event);
  const base = omitUndefinedValues({
    code: typeof query.code === "string" ? query.code : void 0,
    state: typeof query.state === "string" ? query.state : void 0,
    error: typeof query.error === "string" ? query.error : void 0,
    error_description: typeof query.error_description === "string" ? query.error_description : void 0
  });
  const providerSpecificFields = providerConfig[provider].callbackQueryFields ?? [];
  const extras = {};
  for (const field of providerSpecificFields) {
    const key = field;
    const value = query[key];
    if (typeof value === "string") {
      extras[key] = value;
    }
  }
  return {
    ...base,
    ...extras
  };
}
async function refreshToken(refreshTokenValue, providerConfig2, _provider) {
  const requestConfig = {
    url: providerConfig2.tokenEndpoint,
    params: {
      client_secret: providerConfig2.clientSecret,
      refresh_token: refreshTokenValue,
      grant_type: "refresh_token"
    }
  };
  try {
    const tokenResponse = await ofetch(
      requestConfig.url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams(requestConfig.params).toString()
      }
    );
    return tokenResponse;
  } catch (error) {
    const { statusCode, message } = await parseOAuthError(error);
    throw createError({ statusCode, message });
  }
}
function parseTokenField(raw) {
  return /^\d+$/.test(raw) ? parseInt(raw, 10) : raw;
}
async function oAuthTokensAreValid(event, provider) {
  const access_token = getCookie(event, `${provider}_access_token`);
  const refresh_token = getCookie(event, `${provider}_refresh_token`);
  const access_token_expires_at = getCookie(
    event,
    `${provider}_access_token_expires_at`
  );
  if (!access_token || !refresh_token || !access_token_expires_at) return false;
  const expires_in = parseInt(access_token_expires_at, 10);
  const now = Math.floor(Date.now() / 1e3);
  const isAccessTokenExpired = now >= expires_in;
  const base = { access_token, refresh_token, expires_in };
  if (providerConfig[provider].validateRefreshTokenExpiry) {
    const refreshExpiresAt = getCookie(
      event,
      `${provider}_refresh_token_expires_at`
    );
    if (!refreshExpiresAt) return false;
    const refreshExpiry = parseInt(refreshExpiresAt, 10);
    if (isNaN(refreshExpiry) || now >= refreshExpiry) {
      return {
        tokens: {
          ...base
          // fallback to partial fields even if refresh is expired
        },
        status: "expired"
      };
    }
  }
  const additionalFields = getProviderCookieFields(event, provider);
  if (additionalFields === false) return false;
  const tokens = {
    ...base,
    ...additionalFields
  };
  return {
    tokens,
    status: isAccessTokenExpired ? "expired" : "valid"
  };
}
function normalizeRefreshedToken(provider, refreshed, previous) {
  const keysToPreserve = providerConfig[provider].providerSpecificFields;
  const preserved = preserveFields(
    provider,
    previous,
    extractPreservableKeys(keysToPreserve)
  );
  const merged = {
    ...refreshed,
    ...preserved
  };
  if (!merged.refresh_token && previous.refresh_token) {
    merged.refresh_token = previous.refresh_token;
  }
  return merged;
}
function extractPreservableKeys(fields) {
  return fields.map(
    (field) => isStructuredTokenField(field) ? field.key : field
  );
}
function preserveFields(_provider, source, keys) {
  const result = {};
  for (const key of keys) {
    result[key] = source[key];
  }
  return result;
}
function isStructuredTokenField(field) {
  return typeof field === "object" && field !== null && "key" in field;
}
function getProviderCookieFields(event, provider) {
  const result = {};
  for (const { cookieKey, fieldKey } of resolveProviderFieldMeta(provider)) {
    const raw = getCookie(event, cookieKey);
    if (raw == null) return false;
    result[fieldKey] = parseTokenField(raw);
  }
  return result;
}
function setProviderCookieFields(event, tokens, provider, baseOptions) {
  for (const { cookieKey, fieldKey, setter } of resolveProviderFieldMeta(
    provider
  )) {
    const raw = tokens[fieldKey];
    if (raw === void 0) continue;
    const value = setter ? setter(String(raw)) : String(raw);
    if (typeof raw === "string" || typeof raw === "number") {
      setCookie(event, cookieKey, value, baseOptions);
    }
  }
}
function resolveProviderFieldMeta(provider) {
  const fields = providerConfig[provider].providerSpecificFields;
  return fields.flatMap((field) => {
    if (typeof field === "string") {
      return [
        {
          cookieKey: `${provider}_${field}`,
          fieldKey: field
        }
      ];
    }
    if (isStructuredTokenField(field)) {
      const base = {
        cookieKey: field.cookieName ?? `${provider}_${String(field.key)}`,
        fieldKey: field.key
      };
      return field.setter ? [{ ...base, setter: field.setter }] : [base];
    }
    return [];
  });
}

const providerRegistry = /* @__PURE__ */ new Map();
function registerOAuthProvider(provider, config) {
  providerRegistry.set(provider, config);
}
function getOAuthProviderConfig(provider) {
  const config = providerRegistry.get(provider);
  if (!config) {
    throw createError({
      statusCode: 500,
      statusMessage: `OAuth provider "${provider}" is not registered`
    });
  }
  return config;
}
function handleOAuthLogin(provider, options, event) {
  const handler = async (evt) => {
    const config = getOAuthProviderConfig(provider);
    const state = resolveState(evt, provider, options?.state);
    const authUrl = buildAuthUrl({
      authorizeEndpoint: config.authorizeEndpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes: config.scopes,
      state
    });
    if (options?.redirect === true) {
      return sendRedirect(evt, authUrl, 302);
    }
    return { url: authUrl };
  };
  return event ? handler(event) : defineEventHandler(handler);
}
function handleOAuthCallback(provider, options, event) {
  const handler = async (evt) => {
    const query = getQuery(evt);
    const { code, state } = query;
    if (!code || typeof code !== "string") {
      throw createError({
        statusCode: 400,
        statusMessage: "Authorization code missing in callback URL"
      });
    }
    if (!state || typeof state !== "string") {
      throw createError({
        statusCode: 400,
        statusMessage: "State missing in callback URL"
      });
    }
    verifyStateParam(evt, provider, state);
    const parsedState = parseOAuthState(state);
    const config = getOAuthProviderConfig(provider);
    const rawTokens = await exchangeCodeForTokens(code, config);
    const callbackQueryData = parseOAuthCallbackQuery(evt, provider);
    const tokens = setProviderCookies(
      evt,
      rawTokens,
      provider,
      options?.cookieOptions
    );
    const redirectTo = options?.redirectTo || "/";
    if (options?.redirect === false) {
      return { tokens, state: parsedState, callbackQueryData };
    }
    return sendRedirect(evt, redirectTo, 302);
  };
  if (event) {
    if (options?.redirect === false) {
      return handler(event);
    } else {
      return handler(event);
    }
  }
  return defineEventHandler(handler);
}
function defineProtectedRoute(providers, handler, options) {
  return defineEventHandler(async (event) => {
    const ctx = event.context;
    ctx.h3OAuthKit = {};
    for (const provider of providers) {
      const result = await oAuthTokensAreValid(event, provider);
      if (!result) {
        throw createError({
          statusCode: 401,
          message: `Missing or invalid tokens for "${provider}"`
        });
      }
      let tokens = result.tokens;
      if (result.status === "expired") {
        const config = getOAuthProviderConfig(provider);
        const refreshed = await refreshToken(
          result.tokens.refresh_token,
          config);
        if (!refreshed) {
          throw createError({
            statusCode: 401,
            message: `Token refresh failed for "${provider}"`
          });
        }
        const fullToken = normalizeRefreshedToken(provider, refreshed, tokens);
        tokens = setProviderCookies(
          event,
          fullToken,
          provider,
          options?.cookieOptions
        );
      }
      const key = `${provider}_access_token`;
      ctx[key] = tokens.access_token;
      ctx.h3OAuthKit[provider] = tokens;
    }
    return handler(event);
  });
}

export { defineProtectedRoute, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin, providerRegistry, registerOAuthProvider };
