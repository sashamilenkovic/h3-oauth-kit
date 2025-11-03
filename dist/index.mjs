import { getCookie, createError, setCookie, deleteCookie, getQuery, defineEventHandler, isError, sendRedirect } from 'h3';
import { ofetch } from 'ofetch';

const knownProviderConfig = {
  azure: {
    baseCookieFields: [
      "access_token",
      "refresh_token",
      "access_token_expires_at"
    ],
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
    baseCookieFields: [
      "access_token",
      "refresh_token",
      "access_token_expires_at"
    ],
    providerSpecificFields: []
  },
  intuit: {
    baseCookieFields: [
      "access_token",
      "refresh_token",
      "access_token_expires_at"
    ],
    providerSpecificFields: [
      {
        key: "x_refresh_token_expires_in",
        cookieName: "intuit_refresh_token_expires_at",
        setter: (value) => String(Math.floor(Date.now() / 1e3) + Number(value))
      }
    ],
    callbackQueryFields: ["realmId"],
    validateRefreshTokenExpiry: true
  },
  mycase: {
    baseCookieFields: [
      "access_token",
      "refresh_token",
      "access_token_expires_at"
    ],
    providerSpecificFields: []
  }
};
const defaultProviderConfig = {
  baseCookieFields: [
    "access_token",
    "refresh_token",
    "access_token_expires_at"
  ],
  providerSpecificFields: []
};
function getProviderConfig(provider) {
  return knownProviderConfig[provider] || defaultProviderConfig;
}

function generateCodeVerifier() {
  const randomBytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(randomBytes);
}
async function generateCodeChallenge(codeVerifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(hash));
}
function base64UrlEncode(buffer) {
  const base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

async function fetchUserInfo(userInfoEndpoint, accessToken, _provider) {
  if (!userInfoEndpoint) {
    return void 0;
  }
  try {
    const userInfo = await ofetch(
      userInfoEndpoint,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      }
    );
    return userInfo;
  } catch (error) {
    console.error(`Failed to fetch userInfo from ${userInfoEndpoint}:`, error);
    return void 0;
  }
}
function parseIDToken(idToken) {
  if (!idToken) {
    return void 0;
  }
  try {
    const parts = idToken.split(".");
    if (parts.length !== 3) {
      console.error("Invalid ID token format: expected 3 parts");
      return void 0;
    }
    const payload = parts[1];
    const decoded = base64UrlDecode(payload);
    const claims = JSON.parse(decoded);
    if (!claims.iss || !claims.sub || !claims.aud || !claims.exp || !claims.iat) {
      console.error("ID token missing required claims");
      return void 0;
    }
    return claims;
  } catch (error) {
    console.error("Failed to parse ID token:", error);
    return void 0;
  }
}
function base64UrlDecode(base64Url) {
  let base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padding = base64.length % 4;
  if (padding > 0) {
    base64 += "=".repeat(4 - padding);
  }
  const decoded = atob(base64);
  return decodeURIComponent(
    decoded.split("").map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)).join("")
  );
}

function shouldRefreshToken(tokens, thresholdSeconds) {
  const now = Math.floor(Date.now() / 1e3);
  const expiresAt = tokens.expires_in;
  const timeUntilExpiry = expiresAt - now;
  return timeUntilExpiry <= thresholdSeconds && timeUntilExpiry > 0;
}
async function setProviderCookies(event, tokens, provider, options, instanceKey) {
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;
  const base = {
    httpOnly: true,
    secure: true,
    sameSite: options?.sameSite ?? "lax",
    path: options?.path ?? "/"
  };
  const expiresIn = tokens.expires_in;
  const cleanedAccessToken = tokens.access_token.startsWith("Bearer ") ? tokens.access_token.slice(7) : tokens.access_token;
  setCookie(event, `${providerKey}_access_token`, cleanedAccessToken, {
    ...base,
    maxAge: expiresIn
  });
  const expiry = Math.floor(Date.now() / 1e3) + expiresIn;
  setCookie(
    event,
    `${providerKey}_access_token_expires_at`,
    String(expiry),
    base
  );
  const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
  if (tokens.refresh_token) {
    const encryptedRefreshToken = await config.encrypt(tokens.refresh_token);
    let refreshTokenMaxAge = 30 * 24 * 60 * 60;
    if (getProviderConfig(provider).validateRefreshTokenExpiry && hasXRefreshTokenExpiresIn(tokens)) {
      refreshTokenMaxAge = tokens.x_refresh_token_expires_in;
    } else if (options?.refreshTokenMaxAge) {
      refreshTokenMaxAge = options.refreshTokenMaxAge;
    }
    setCookie(event, `${providerKey}_refresh_token`, encryptedRefreshToken, {
      ...base,
      maxAge: refreshTokenMaxAge
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
  state,
  codeChallenge,
  codeChallengeMethod
}) {
  const url = new URL(authorizeEndpoint);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scopes.join(" "));
  url.searchParams.set("state", state);
  if (codeChallenge && codeChallengeMethod) {
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", codeChallengeMethod);
  }
  return url.toString();
}
function parseProviderKey(providerKey, delimiter = ":") {
  const parts = providerKey.split(delimiter);
  if (parts.length === 1) {
    return { provider: parts[0], preserveInstance: false };
  }
  if (parts.length === 2) {
    if (parts[1] === "preserve") {
      return { provider: parts[0], preserveInstance: true };
    }
    return {
      provider: parts[0],
      instanceKey: parts[1],
      preserveInstance: false
    };
  }
  if (parts.length === 3 && parts[2] === "preserve") {
    return {
      provider: parts[0],
      instanceKey: parts[1],
      preserveInstance: true
    };
  }
  return { provider: parts[0], instanceKey: parts[1], preserveInstance: false };
}
function resolveState(event, providerKey, userState) {
  const resolved = typeof userState === "function" ? userState(event) : userState ?? {};
  if (typeof resolved !== "object" || resolved === null || Array.isArray(resolved)) {
    throw new TypeError("OAuth state must be a plain object");
  }
  const csrf = crypto.randomUUID();
  const { provider: _provider, instanceKey } = parseProviderKey(providerKey);
  const stateObject = {
    ...resolved,
    csrf,
    providerKey,
    ...instanceKey && { instanceKey }
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
async function exchangeCodeForTokens(code, config, _provider, codeVerifier) {
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
  if (codeVerifier) {
    params.code_verifier = codeVerifier;
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
  const providerSpecificFields = getProviderConfig(provider).callbackQueryFields ?? [];
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
async function refreshToken(refreshTokenValue, providerConfig, _provider) {
  const requestConfig = {
    url: providerConfig.tokenEndpoint,
    params: {
      client_id: providerConfig.clientId,
      client_secret: providerConfig.clientSecret,
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
  const providerKey = getProviderKey(provider, instanceKey);
  const access_token = getCookie(event, `${providerKey}_access_token`);
  const refresh_token = getCookie(event, `${providerKey}_refresh_token`);
  const access_token_expires_at = getCookie(
    event,
    `${providerKey}_access_token_expires_at`
  );
  if (!refresh_token) {
    return false;
  }
  const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
  const decryptedRefreshToken = await config.decrypt(refresh_token);
  if (!access_token) {
    return {
      tokens: {
        refresh_token: decryptedRefreshToken
        // other fields will be filled in after refresh
      },
      status: "expired"
    };
  }
  if (!access_token_expires_at) {
    return {
      tokens: {
        access_token,
        refresh_token: decryptedRefreshToken
      },
      status: "expired"
    };
  }
  const expires_in = parseInt(access_token_expires_at, 10);
  const now = Math.floor(Date.now() / 1e3);
  const isAccessTokenExpired = now >= expires_in;
  const base = {
    access_token,
    refresh_token: decryptedRefreshToken,
    expires_in
  };
  if (getProviderConfig(provider).validateRefreshTokenExpiry) {
    const refreshExpiresAt = getCookie(
      event,
      `${providerKey}_refresh_token_expires_at`
    );
    if (!refreshExpiresAt) {
      return false;
    }
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
  if (additionalFields === false) {
    return false;
  }
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
  const keysToPreserve = getProviderConfig(provider).providerSpecificFields;
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
  const base = getProviderConfig(provider).baseCookieFields.map(
    (field) => `${providerKey}_${field}`
  );
  const specific = getProviderConfig(provider).providerSpecificFields.map(
    (field) => {
      const rawKey = typeof field === "string" ? `${provider}_${field}` : field.cookieName ?? `${provider}_${String(field.key)}`;
      return rawKey.replace(`${provider}_`, `${providerKey}_`);
    }
  );
  return [...base, ...specific];
}
function resolveProviderFieldMeta(provider) {
  const fields = getProviderConfig(provider).providerSpecificFields;
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
function getProviderKey(provider, instanceKey, preserveInstance, delimiter = ":") {
  let key = instanceKey ? `${provider}${delimiter}${instanceKey}` : provider;
  if (preserveInstance) {
    key += `${delimiter}preserve`;
  }
  return key;
}
function clearNonPreservedCookies(event, provider) {
  for (const cookieName of getProviderCookieKeys(provider)) {
    deleteCookie(event, cookieName);
  }
}
function discoverProviderInstance(event, provider) {
  const globalKey = `${provider}_refresh_token`;
  if (getCookie(event, globalKey)) {
    return void 0;
  }
  const cookies = event.node.req.headers.cookie;
  if (!cookies) return void 0;
  const cookiePattern = new RegExp(`${provider}:([^_]+)_refresh_token=`);
  const matches = cookies.match(cookiePattern);
  if (matches && matches[1]) {
    return matches[1];
  }
  return void 0;
}
function hasXRefreshTokenExpiresIn(obj) {
  return typeof obj === "object" && obj !== null && "x_refresh_token_expires_in" in obj && typeof obj.x_refresh_token_expires_in === "number";
}

const IV_LENGTH = 16;
function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
function uint8ArrayToHex(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
async function createEncryptionKey(hexKey) {
  if (!hexKey || hexKey.length !== 64) {
    throw new Error(
      "Encryption key must be a 64-character hex string (32 bytes)."
    );
  }
  const keyBytes = hexToUint8Array(hexKey);
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-CBC" },
    false,
    ["encrypt", "decrypt"]
  );
}
function createEncryption(hexKey) {
  const keyPromise = createEncryptionKey(hexKey);
  async function encrypt(text) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const key = await keyPromise;
    const textBytes = new TextEncoder().encode(text);
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv
      },
      key,
      textBytes
    );
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    return uint8ArrayToHex(iv) + ":" + uint8ArrayToHex(encryptedBytes);
  }
  async function decrypt(encryptedText) {
    if (typeof encryptedText !== "string") {
      throw new Error("Encrypted text must be a string");
    }
    const [ivHex, encryptedHex] = encryptedText.split(":");
    if (!ivHex || !encryptedHex) {
      throw new Error("Invalid encrypted text format");
    }
    const iv = hexToUint8Array(ivHex);
    if (iv.length !== IV_LENGTH) {
      throw new Error("Invalid IV length in encrypted text");
    }
    const encryptedBytes = hexToUint8Array(encryptedHex);
    const key = await keyPromise;
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv
      },
      key,
      encryptedBytes
    );
    return new TextDecoder().decode(decryptedBuffer);
  }
  return { encrypt, decrypt };
}

const providerRegistry = /* @__PURE__ */ new Map();
function useOAuthRegistry(encryptionKey) {
  const { encrypt, decrypt } = createEncryption(encryptionKey);
  function registerOAuthProvider(provider, instanceOrConfig, maybeConfig) {
    const isScoped = typeof instanceOrConfig === "string";
    const key = isScoped ? `${provider}:${instanceOrConfig}` : provider;
    const userConfig = isScoped ? maybeConfig : instanceOrConfig;
    const config = {
      ...userConfig,
      encrypt,
      decrypt
    };
    providerRegistry.set(key, config);
  }
  return {
    registerOAuthProvider
  };
}
function getOAuthProviderConfig(provider, instanceKey) {
  const key = getProviderKey(provider, instanceKey);
  const config = providerRegistry.get(key);
  if (!config) {
    throw createError({
      statusCode: 500,
      statusMessage: `OAuth provider "${key}" is not registered`
    });
  }
  return config;
}
function hasOAuthProviderConfig(provider, instanceKey) {
  const key = getProviderKey(provider, instanceKey);
  return providerRegistry.has(key);
}
function handleOAuthLogin(provider, instanceKey, optionsOrEvent, maybeEvent) {
  const isScoped = typeof instanceKey === "string";
  const resolvedInstanceKey = isScoped ? instanceKey : void 0;
  const options = isScoped ? optionsOrEvent : instanceKey ?? {};
  const event = isScoped ? maybeEvent : optionsOrEvent;
  const handler = async (evt) => {
    const config = resolvedInstanceKey ? getOAuthProviderConfig(provider, resolvedInstanceKey) : getOAuthProviderConfig(provider);
    const providerKey = getProviderKey(
      provider,
      resolvedInstanceKey,
      options?.preserveInstance
    );
    const state = resolveState(evt, providerKey, options?.state);
    const pkceParams = {};
    if (config.usePKCE) {
      const codeVerifier = generateCodeVerifier();
      pkceParams.codeChallenge = await generateCodeChallenge(codeVerifier);
      pkceParams.codeChallengeMethod = "S256";
      setCookie(evt, `oauth_pkce_${providerKey}`, codeVerifier, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 300
        // 5 minutes (same as CSRF)
      });
    }
    const authUrl = buildAuthUrl({
      authorizeEndpoint: config.authorizeEndpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scopes: config.scopes,
      state,
      ...pkceParams
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
      const {
        provider: _baseProvider,
        instanceKey,
        preserveInstance
      } = parseProviderKey(parsedState.providerKey);
      const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
      let codeVerifier;
      if (config.usePKCE) {
        const cookieKey = `oauth_pkce_${parsedState.providerKey}`;
        codeVerifier = getCookie(evt, cookieKey);
        if (!codeVerifier) {
          throw createError({
            statusCode: 400,
            statusMessage: "PKCE code_verifier missing from callback"
          });
        }
        deleteCookie(evt, cookieKey);
      }
      const rawTokens = await exchangeCodeForTokens(
        code,
        config,
        provider,
        codeVerifier
      );
      if (options?.instanceEquivalent) {
        const isValid = await options.instanceEquivalent(
          rawTokens,
          evt,
          provider,
          instanceKey
        );
        if (!isValid) {
          throw createError({
            statusCode: 401,
            statusMessage: "User validation failed after OAuth callback"
          });
        }
      }
      if (!preserveInstance) {
        clearNonPreservedCookies(evt, provider);
      }
      const tokens = await setProviderCookies(
        evt,
        rawTokens,
        provider,
        options?.cookieOptions,
        instanceKey
      );
      if (config.hooks?.onLogin) {
        await config.hooks.onLogin(evt, tokens, provider, instanceKey);
      }
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
        message,
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
    ctx.h3OAuthKitInstances = {};
    for (const def of providers) {
      const isScoped = typeof def !== "string";
      const provider = isScoped ? def.provider : def;
      try {
        let instanceKey;
        if (isScoped) {
          if ("instanceKey" in def) {
            instanceKey = def.instanceKey;
          } else if ("instanceResolver" in def) {
            instanceKey = await def.instanceResolver(event);
          }
        }
        const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
        let providerKey = getProviderKey(provider, instanceKey);
        let result = await oAuthTokensAreValid(event, provider, instanceKey);
        if (!result && !isScoped) {
          const discoveredInstanceKey = discoverProviderInstance(
            event,
            provider
          );
          if (discoveredInstanceKey) {
            instanceKey = discoveredInstanceKey;
            providerKey = getProviderKey(provider, instanceKey);
            result = await oAuthTokensAreValid(event, provider, instanceKey);
          }
        }
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
        const shouldRefresh = result.status === "expired" || result.status === "valid" && options?.refreshThreshold && shouldRefreshToken(tokens, options.refreshThreshold);
        if (shouldRefresh) {
          const oldTokens = tokens;
          const refreshed = await refreshToken(
            tokens.refresh_token,
            config,
            provider
          );
          if (!refreshed) {
            if (config.hooks?.onTokenExpired) {
              await config.hooks.onTokenExpired(event, provider, instanceKey);
            }
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
          tokens = await setProviderCookies(
            event,
            fullToken,
            provider,
            options?.cookieOptions,
            instanceKey
          );
          if (config.hooks?.onTokenRefresh) {
            await config.hooks.onTokenRefresh(
              event,
              oldTokens,
              tokens,
              provider,
              instanceKey
            );
          }
        }
        const userInfo = await fetchUserInfo(
          config.userInfoEndpoint,
          tokens.access_token,
          provider
        );
        let id_token_claims;
        if ("id_token" in tokens && typeof tokens.id_token === "string") {
          id_token_claims = parseIDToken(tokens.id_token);
        }
        ctx.h3OAuthKit[providerKey] = {
          ...tokens,
          userInfo,
          id_token_claims
        };
        const baseProvider = isScoped ? def.provider : def;
        ctx.h3OAuthKitInstances[baseProvider] = instanceKey;
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
    return handler(
      event
    );
  });
}
function deleteProviderCookies(event, provider, instanceKey) {
  if (instanceKey) {
    for (const cookieName of getProviderCookieKeys(provider, instanceKey)) {
      deleteCookie(event, cookieName);
    }
  } else {
    const registeredKeys = Array.from(providerRegistry.keys());
    const providerKeys = registeredKeys.filter(
      (key) => key === provider || key.startsWith(`${provider}:`)
    );
    for (const providerKey of providerKeys) {
      const extractedInstanceKey = providerKey.includes(":") ? providerKey.split(":")[1] : void 0;
      for (const cookieName of getProviderCookieKeys(
        provider,
        extractedInstanceKey
      )) {
        deleteCookie(event, cookieName);
      }
    }
  }
}
function handleOAuthLogout(providers, options, event) {
  const normalized = providers.map(
    (p) => typeof p === "string" ? { provider: p } : p
  );
  const handler = async (evt) => {
    for (const { provider, instanceKey } of normalized) {
      if (hasOAuthProviderConfig(provider, instanceKey)) {
        const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
        if (config.hooks?.onLogout) {
          await config.hooks.onLogout(evt, provider, instanceKey);
        }
      }
      deleteProviderCookies(evt, provider, instanceKey);
    }
    if (options?.redirectTo) {
      await sendRedirect(evt, options.redirectTo, 302);
      return;
    }
    return {
      loggedOut: true,
      providers: normalized
    };
  };
  return event ? handler(event) : defineEventHandler(handler);
}
function getDiscoveredProviderTokens(context, provider) {
  if (context[provider]) {
    return {
      tokens: context[provider],
      key: provider
    };
  }
  for (const [key, tokens] of Object.entries(context)) {
    if (key.startsWith(`${provider}:`)) {
      return { tokens, key };
    }
  }
  return void 0;
}
function typedInstanceResolver(resolver) {
  return resolver;
}
function withInstanceKeys(provider, instanceKeys, resolver) {
  return {
    provider,
    instanceResolver: resolver,
    __instanceKeys: instanceKeys
  };
}
async function revokeOAuthTokens(event, provider, options) {
  const { revokeRemote = true, instanceKey } = options || {};
  const hasConfig = hasOAuthProviderConfig(provider, instanceKey);
  if (hasConfig && revokeRemote) {
    const config = instanceKey ? getOAuthProviderConfig(provider, instanceKey) : getOAuthProviderConfig(provider);
    if (config.revokeEndpoint) {
      try {
        const result = await oAuthTokensAreValid(event, provider, instanceKey);
        if (result && result.tokens.access_token) {
          await ofetch(config.revokeEndpoint, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
              token: result.tokens.access_token,
              client_id: config.clientId,
              client_secret: config.clientSecret
            }).toString()
          });
        }
      } catch (error) {
        console.error(
          `Failed to revoke token remotely for ${provider}:`,
          error
        );
      }
    }
  }
  deleteProviderCookies(event, provider, instanceKey);
}
async function checkTokenStatus(event, provider, instanceKey) {
  const result = await oAuthTokensAreValid(event, provider, instanceKey);
  if (!result) {
    const status2 = {
      isValid: false,
      requiresRefresh: false,
      hasRefreshToken: false,
      provider
    };
    if (instanceKey) {
      status2.instanceKey = instanceKey;
    }
    return status2;
  }
  const now = Math.floor(Date.now() / 1e3);
  const expiresAt = result.tokens.expires_in;
  const expiresIn = expiresAt - now;
  const isExpired = result.status === "expired";
  const status = {
    isValid: !isExpired,
    expiresIn: expiresIn > 0 ? expiresIn : 0,
    expiresAt: new Date(expiresAt * 1e3).toISOString(),
    requiresRefresh: isExpired,
    hasRefreshToken: !!result.tokens.refresh_token,
    provider
  };
  if (instanceKey) {
    status.instanceKey = instanceKey;
  }
  return status;
}

export { checkTokenStatus, defineProtectedRoute, deleteProviderCookies, getDiscoveredProviderTokens, getOAuthProviderConfig, handleOAuthCallback, handleOAuthLogin, handleOAuthLogout, hasOAuthProviderConfig, providerRegistry, revokeOAuthTokens, typedInstanceResolver, useOAuthRegistry, withInstanceKeys };
