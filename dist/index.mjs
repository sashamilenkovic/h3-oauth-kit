import { getCookie, createError, setCookie, deleteCookie, getQuery, defineEventHandler, isError, sendRedirect } from 'h3';
import { ofetch } from 'ofetch';
import crypto$1 from 'crypto';

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

const IV_LENGTH = 16;
const rawKey = process.env.H3_OAUTH_ENCRYPTION_KEY;
if (!rawKey || rawKey.length !== 64) {
  throw new Error(
    "[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)."
  );
}
const ENCRYPTION_KEY = Buffer.from(rawKey, "hex");
function encrypt(text) {
  const iv = crypto$1.randomBytes(IV_LENGTH);
  const cipher = crypto$1.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return iv.toString("hex") + ":" + encrypted.toString("hex");
}
function decrypt(encryptedText) {
  const [ivHex, encryptedHex] = encryptedText.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const decipher = crypto$1.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);
  return decrypted.toString();
}

function setProviderCookies(event, tokens, provider, options, instanceKey) {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;
  const base = {
    httpOnly: true,
    secure: true,
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/"
  };
  const cleanedAccessToken = tokens.access_token.startsWith("Bearer ") ? tokens.access_token.slice(7) : tokens.access_token;
  setCookie(event, `${providerKey}_access_token`, cleanedAccessToken, {
    ...base,
    maxAge: tokens.expires_in
  });
  const expiry = Math.floor(Date.now() / 1e3) + tokens.expires_in;
  setCookie(
    event,
    `${providerKey}_access_token_expires_at`,
    String(expiry),
    base
  );
  if (tokens.refresh_token) {
    const encryptedRefreshToken = encrypt(tokens.refresh_token);
    setCookie(event, `${providerKey}_refresh_token`, encryptedRefreshToken, {
      ...base,
      maxAge: 30 * 24 * 60 * 60
      // 30 days
    });
  }
  setProviderCookieFields(event, tokens, provider, providerKey, base);
  return tokens;
}
async function parseError(error) {
  let statusCode = 500;
  let message = "h3-oauth-kit error";
  if (isFetchErrorWithResponse(error)) {
    const response = error.response;
    if (typeof response.status === "number") {
      statusCode = response.status;
    }
    if (typeof response.json === "function") {
      try {
        const json = await response.json();
        if (isOAuthErrorResponse(json)) {
          message = json.error_description || json.error || message;
        }
      } catch {
      }
    }
  }
  if (message === "h3-oauth-kit error" && isErrorWithMessage(error)) {
    message = error.message;
  }
  return { statusCode, message };
}
function isFetchErrorWithResponse(error) {
  if (typeof error === "object" && error !== null && "response" in error) {
    const maybeResponse = error.response;
    return typeof maybeResponse === "object" && maybeResponse !== null && ("status" in maybeResponse || "json" in maybeResponse);
  }
  return false;
}
function isOAuthErrorResponse(json) {
  return typeof json === "object" && json !== null && ("error" in json || "error_description" in json);
}
function isErrorWithMessage(error) {
  return typeof error === "object" && error !== null && "message" in error && typeof error.message === "string";
}
function omitUndefinedValues(input) {
  return Object.fromEntries(
    Object.entries(input).filter(([_, v]) => v !== void 0)
  );
}
function parseOAuthState(rawState) {
  try {
    const decoded = Buffer.from(
      decodeURIComponent(rawState),
      "base64url"
    ).toString("utf-8");
    const parsed = JSON.parse(decoded);
    if (typeof parsed !== "object" || parsed === null || typeof parsed.csrf !== "string" || typeof parsed.providerKey !== "string") {
      throw new Error("Invalid state structure");
    }
    return parsed;
  } catch {
    throw createError({
      statusCode: 400,
      statusMessage: "Invalid or malformed OAuth state parameter"
    });
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
function resolveState(event, providerKey, userState) {
  const resolved = typeof userState === "function" ? userState(event) : userState ?? {};
  if (typeof resolved !== "object" || resolved === null || Array.isArray(resolved)) {
    throw new TypeError("OAuth state must be a plain object");
  }
  const csrf = crypto.randomUUID();
  const stateObject = {
    ...resolved,
    csrf,
    providerKey
  };
  const encodedState = encodeURIComponent(
    Buffer.from(JSON.stringify(stateObject)).toString("base64url")
  );
  setCookie(event, `oauth_csrf_${providerKey}`, csrf, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 300
    // 5 minutes
  });
  return encodedState;
}
function verifyStateParam(event, parsedState) {
  const { csrf, providerKey } = parsedState;
  const cookieKey = `oauth_csrf_${providerKey}`;
  const expected = getCookie(event, cookieKey);
  if (!expected || csrf !== expected) {
    throw createError({
      statusCode: 401,
      statusMessage: `CSRF mismatch for OAuth callback [${providerKey}]`
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
    const { statusCode, message } = await parseError(error);
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
    const { statusCode, message } = await parseError(error);
    throw createError({ statusCode, message });
  }
}
function parseTokenField(raw) {
  return /^\d+$/.test(raw) ? parseInt(raw, 10) : raw;
}
async function oAuthTokensAreValid(event, provider, instanceKey) {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;
  const access_token = getCookie(event, `${providerKey}_access_token`);
  const refresh_token = getCookie(event, `${providerKey}_refresh_token`);
  const access_token_expires_at = getCookie(
    event,
    `${providerKey}_access_token_expires_at`
  );
  if (!access_token || !refresh_token || !access_token_expires_at) return false;
  const encryptedRefreshToken = decrypt(refresh_token);
  const expires_in = parseInt(access_token_expires_at, 10);
  const now = Math.floor(Date.now() / 1e3);
  const isAccessTokenExpired = now >= expires_in;
  const base = {
    access_token,
    refresh_token: encryptedRefreshToken,
    expires_in
  };
  if (providerConfig[provider].validateRefreshTokenExpiry) {
    const refreshExpiresAt = getCookie(
      event,
      `${providerKey}_refresh_token_expires_at`
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
  const additionalFields = getProviderCookieFields(
    event,
    provider,
    providerKey
  );
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
function getProviderCookieFields(event, provider, providerKey) {
  const result = {};
  for (const { cookieKey, fieldKey } of resolveProviderFieldMeta(provider)) {
    const scopedCookieKey = cookieKey.replace(
      `${provider}_`,
      `${providerKey}_`
    );
    const raw = getCookie(event, scopedCookieKey);
    if (raw == null) return false;
    result[fieldKey] = parseTokenField(raw);
  }
  return result;
}
function setProviderCookieFields(event, tokens, provider, providerKey, baseOptions) {
  for (const { cookieKey, fieldKey, setter } of resolveProviderFieldMeta(
    provider
  )) {
    const raw = tokens[fieldKey];
    if (raw === void 0) continue;
    const value = setter ? setter(String(raw)) : String(raw);
    if (typeof raw === "string" || typeof raw === "number") {
      const scopedCookieKey = cookieKey.replace(
        `${provider}_`,
        `${providerKey}_`
      );
      setCookie(event, scopedCookieKey, value, baseOptions);
    }
  }
}
function getProviderCookieKeys(provider, instanceKey) {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;
  const base = [
    `${providerKey}_access_token`,
    `${providerKey}_refresh_token`,
    `${providerKey}_access_token_expires_at`
  ];
  const specific = providerConfig[provider].providerSpecificFields.map(
    (field) => {
      const rawKey = typeof field === "string" ? `${provider}_${field}` : field.cookieName ?? `${provider}_${String(field.key)}`;
      return rawKey.replace(`${provider}_`, `${providerKey}_`);
    }
  );
  return [...base, ...specific];
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
function getProviderKey(provider, instanceKey, delimiter = ":") {
  return instanceKey ? `${provider}${delimiter}${instanceKey}` : provider;
}

const providerRegistry = /* @__PURE__ */ new Map();
function registerOAuthProvider(provider, instanceOrConfig, maybeConfig) {
  const isScoped = typeof instanceOrConfig === "string";
  const key = isScoped ? `${provider}:${instanceOrConfig}` : provider;
  const config = isScoped ? maybeConfig : instanceOrConfig;
  providerRegistry.set(key, config);
}
function getOAuthProviderConfig(provider, instanceKey) {
  const key = instanceKey ? `${provider}:${instanceKey}` : provider;
  const config = providerRegistry.get(key);
  if (!config) {
    throw createError({
      statusCode: 500,
      statusMessage: `OAuth provider "${key}" is not registered`
    });
  }
  return config;
}
function handleOAuthLogin(provider, instanceKey, optionsOrEvent, maybeEvent) {
  const isScoped = typeof instanceKey === "string";
  const resolvedInstanceKey = isScoped ? instanceKey : void 0;
  const options = isScoped ? optionsOrEvent : instanceKey ?? {};
  const event = isScoped ? maybeEvent : optionsOrEvent;
  const handler = async (evt) => {
    const config = resolvedInstanceKey ? getOAuthProviderConfig(provider, resolvedInstanceKey) : getOAuthProviderConfig(provider);
    const state = resolveState(
      evt,
      resolvedInstanceKey ? `${provider}:${resolvedInstanceKey}` : provider,
      options?.state
    );
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
    try {
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
      const parsedState = parseOAuthState(state);
      verifyStateParam(evt, parsedState);
      const config = parsedState.instanceKey ? getOAuthProviderConfig(provider, parsedState.instanceKey) : getOAuthProviderConfig(provider);
      const rawTokens = await exchangeCodeForTokens(code, config, provider);
      const tokens = setProviderCookies(
        evt,
        rawTokens,
        provider,
        options?.cookieOptions,
        parsedState.instanceKey
      );
      const redirectTo = options?.redirectTo || "/";
      if (options?.redirect === false) {
        const callbackQueryData = parseOAuthCallbackQuery(evt, provider);
        return { tokens, state: parsedState, callbackQueryData };
      }
      return sendRedirect(evt, redirectTo, 302);
    } catch (error) {
      if (options?.onError) {
        const result = await options.onError(error, evt, provider);
        if (result !== void 0) return result;
      }
      if (isError(error)) {
        throw error;
      }
      const { statusCode, message } = await parseError(error);
      throw createError({
        statusCode,
        statusMessage: message,
        cause: error
      });
    }
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
    for (const def of providers) {
      const isScoped = typeof def !== "string";
      const provider = isScoped ? def.provider : def;
      const instanceKey = isScoped ? def.instanceKey : void 0;
      const providerKey = getProviderKey(provider, instanceKey);
      try {
        const result = await oAuthTokensAreValid(event, provider, instanceKey);
        if (!result) {
          const error = createError({
            statusCode: 401,
            message: `Missing or invalid tokens for "${providerKey}"`
          });
          if (options?.onAuthFailure) {
            const response = await options.onAuthFailure(
              event,
              provider,
              "missing-or-invalid-tokens",
              error
            );
            if (response !== void 0) return response;
          }
          throw error;
        }
        let tokens = result.tokens;
        if (result.status === "expired") {
          const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
          const refreshed = await refreshToken(
            tokens.refresh_token,
            config,
            provider
          );
          if (!refreshed) {
            const error = createError({
              statusCode: 401,
              message: `Token refresh failed for "${providerKey}"`
            });
            if (options?.onAuthFailure) {
              const response = await options.onAuthFailure(
                event,
                provider,
                "token-refresh-failed",
                error
              );
              if (response !== void 0) return response;
            }
            throw error;
          }
          const fullToken = normalizeRefreshedToken(
            provider,
            refreshed,
            tokens
          );
          tokens = setProviderCookies(
            event,
            fullToken,
            provider,
            options?.cookieOptions,
            instanceKey
          );
        }
        ctx.h3OAuthKit[providerKey] = tokens;
      } catch (error) {
        if (options?.onAuthFailure) {
          const response = await options.onAuthFailure(
            event,
            provider,
            "error-occurred",
            error
          );
          if (response !== void 0) return response;
        }
        if (isError(error)) {
          throw error;
        }
        const { statusCode, message } = await parseError(error);
        throw createError({
          statusCode,
          statusMessage: message,
          cause: error
        });
      }
    }
    return handler(event);
  });
}
function deleteProviderCookies(event, provider, instanceKey) {
  for (const cookieName of getProviderCookieKeys(provider, instanceKey)) {
    deleteCookie(event, cookieName);
  }
}
function handleOAuthLogout(providers, options, event) {
  const handler = async (evt) => {
    for (const { provider, instanceKey } of providers) {
      deleteProviderCookies(evt, provider, instanceKey);
    }
    if (options?.redirectTo) {
      await sendRedirect(evt, options.redirectTo, 302);
      return;
    }
    return {
      loggedOut: true,
      providers
    };
  };
  return event ? handler(event) : defineEventHandler(handler);
}

export { defineProtectedRoute, deleteProviderCookies, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin, handleOAuthLogout, providerRegistry, registerOAuthProvider };
