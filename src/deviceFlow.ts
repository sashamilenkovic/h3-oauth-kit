/**
 * Device Authorization Flow (RFC 8628)
 *
 * This module is tree-shakable - only bundled if you import it.
 * Import directly for best tree-shaking:
 *   import { initiateDeviceFlow, pollForDeviceToken } from '@milencode/h3-oauth-kit/device-flow'
 */

import { ofetch } from 'ofetch';
import type {
  OAuthProvider,
  DeviceAuthorizationRequest,
  DeviceAuthorizationResponse,
  DeviceTokenRequest,
  DeviceTokenResponse,
  DeviceFlowError,
  DeviceFlowOptions,
  DeviceTokenPollOptions,
} from './types';
import { providerRegistry } from './index';

/**
 * Initiates the Device Authorization Flow (RFC 8628)
 *
 * The Device Authorization Flow is designed for devices that lack a web browser
 * or have limited input capabilities (TVs, CLI tools, IoT devices, etc.).
 *
 * ### How it works:
 * 1. Device calls this function → receives `user_code` and `verification_uri`
 * 2. Device displays these to the user
 * 3. User opens the URL on another device (phone/computer) and enters the code
 * 4. Device polls for token using `pollForDeviceToken()`
 *
 * ### Use Cases:
 * - **CLI tools**: Authenticate users from terminal
 * - **Smart TVs**: Login flow for streaming apps
 * - **IoT devices**: Devices without browsers
 * - **CI/CD**: Authenticate build pipelines
 *
 * ### Examples:
 *
 * **Basic CLI Tool:**
 * ```typescript
 * import { initiateDeviceFlow, pollForDeviceToken } from '@milencode/h3-oauth-kit/device-flow';
 *
 * const deviceAuth = await initiateDeviceFlow('azure', {
 *   scopes: ['User.Read', 'Mail.Send'],
 * });
 *
 * console.log('Please visit:', deviceAuth.verification_uri);
 * console.log('And enter code:', deviceAuth.user_code);
 *
 * // Poll for token (waits for user to authorize)
 * const tokens = await pollForDeviceToken('azure', deviceAuth.device_code);
 * console.log('Success! Access token:', tokens.access_token);
 * ```
 *
 * **With Progress Updates:**
 * ```typescript
 * const tokens = await pollForDeviceToken('azure', deviceCode, {
 *   onPoll: (attempt, seconds) => {
 *     console.log(`Waiting for authorization... (${seconds}s elapsed)`);
 *   },
 *   maxWaitTime: 600, // Wait up to 10 minutes
 * });
 * ```
 *
 * **QR Code for Mobile:**
 * ```typescript
 * import QRCode from 'qrcode';
 *
 * const deviceAuth = await initiateDeviceFlow('github');
 *
 * // Generate QR code for mobile scanning
 * const qr = await QRCode.toString(
 *   deviceAuth.verification_uri_complete || deviceAuth.verification_uri,
 *   { type: 'terminal' }
 * );
 *
 * console.log(qr);
 * console.log('Or manually enter code:', deviceAuth.user_code);
 * ```
 *
 * @param provider - The OAuth provider (e.g., 'azure', 'github')
 * @param options - Optional configuration (scopes, instanceKey)
 * @returns A promise that resolves to the device authorization response
 * @throws Error if the provider doesn't support device flow or if the request fails
 */
export async function initiateDeviceFlow(
  provider: OAuthProvider,
  options: DeviceFlowOptions = {},
): Promise<DeviceAuthorizationResponse> {
  const { scopes, instanceKey } = options;

  // Construct provider key
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  // Get provider config
  const config = providerRegistry.get(providerKey);
  if (!config) {
    throw new Error(
      `Provider "${providerKey}" is not registered. Call registerOAuthProvider() first.`,
    );
  }

  // Check if provider supports device flow
  if (
    !('deviceAuthorizationEndpoint' in config) ||
    !config.deviceAuthorizationEndpoint
  ) {
    throw new Error(
      `Provider "${providerKey}" does not have a device authorization endpoint configured. ` +
        `Add 'deviceAuthorizationEndpoint' to the provider configuration.`,
    );
  }

  // Prepare device authorization request
  const requestBody: DeviceAuthorizationRequest = {
    client_id: config.clientId,
  };

  // Add scopes
  const requestScopes = scopes || config.scopes;
  if (requestScopes && requestScopes.length > 0) {
    requestBody.scope = requestScopes.join(' ');
  }

  // Make device authorization request
  try {
    const response = await ofetch<DeviceAuthorizationResponse>(
      config.deviceAuthorizationEndpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams(requestBody as Record<string, string>),
      },
    );

    return response;
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error';
    throw new Error(
      `Failed to initiate device flow for "${providerKey}": ${errorMessage}`,
    );
  }
}

/**
 * Polls for device token after user authorization (RFC 8628 Section 3.4)
 *
 * After calling `initiateDeviceFlow()` and showing the user code to the user,
 * call this function to wait for the user to authorize the device.
 *
 * This function automatically handles:
 * - Polling at the correct interval
 * - Backing off when told to slow down
 * - Timing out after max wait time
 * - Handling authorization pending, access denied, expired token errors
 *
 * ### Examples:
 *
 * **Basic Usage:**
 * ```typescript
 * const deviceAuth = await initiateDeviceFlow('azure');
 * console.log('Go to:', deviceAuth.verification_uri);
 * console.log('Enter code:', deviceAuth.user_code);
 *
 * const tokens = await pollForDeviceToken('azure', deviceAuth.device_code);
 * // Returns when user authorizes (or throws if denied/timeout)
 * ```
 *
 * **With Progress Callback:**
 * ```typescript
 * const tokens = await pollForDeviceToken('azure', deviceCode, {
 *   onPoll: async (attempt, secondsElapsed) => {
 *     await sendNotification(`Still waiting... (attempt ${attempt})`);
 *   },
 * });
 * ```
 *
 * **Custom Timeouts:**
 * ```typescript
 * try {
 *   const tokens = await pollForDeviceToken('github', deviceCode, {
 *     maxWaitTime: 300, // 5 minutes
 *     pollInterval: 3,  // Poll every 3 seconds
 *   });
 * } catch (error) {
 *   if (error.message.includes('timed out')) {
 *     console.log('User took too long to authorize');
 *   }
 * }
 * ```
 *
 * @param provider - The OAuth provider
 * @param deviceCode - The device_code from initiateDeviceFlow()
 * @param options - Optional configuration (maxWaitTime, pollInterval, onPoll, instanceKey)
 * @returns A promise that resolves to the token response when authorized
 * @throws Error if authorization is denied, expires, or times out
 */
export async function pollForDeviceToken(
  provider: OAuthProvider,
  deviceCode: string,
  options: DeviceTokenPollOptions = {},
): Promise<DeviceTokenResponse> {
  const {
    maxWaitTime = 300, // 5 minutes default
    pollInterval,
    instanceKey,
    onPoll,
  } = options;

  // Construct provider key
  const providerKey = instanceKey ? `${provider}:${instanceKey}` : provider;

  // Get provider config
  const config = providerRegistry.get(providerKey);
  if (!config) {
    throw new Error(
      `Provider "${providerKey}" is not registered. Call registerOAuthProvider() first.`,
    );
  }

  // Check provider has token endpoint
  if (!config.tokenEndpoint) {
    throw new Error(
      `Provider "${providerKey}" does not have a token endpoint configured.`,
    );
  }

  // Determine polling interval (use custom or server-recommended, default 5s)
  let currentInterval = pollInterval || 5; // Default to 5 seconds

  const startTime = Date.now();
  let attempt = 0;

  while (true) {
    attempt++;
    const secondsElapsed = Math.floor((Date.now() - startTime) / 1000);

    // Check timeout
    if (secondsElapsed >= maxWaitTime) {
      throw new Error(
        `Device authorization timed out after ${maxWaitTime} seconds`,
      );
    }

    // Call onPoll callback
    if (onPoll) {
      await onPoll(attempt, secondsElapsed);
    }

    // Prepare token request
    const requestBody: DeviceTokenRequest = {
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: deviceCode,
      client_id: config.clientId,
    };

    try {
      const response = await ofetch<DeviceTokenResponse>(
        config.tokenEndpoint,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
          body: new URLSearchParams(requestBody as Record<string, string>),
        },
      );

      // Success! Return tokens
      return response;
    } catch (error: unknown) {
      // Handle device flow errors
      const deviceError = error as { data?: DeviceFlowError };
      const errorCode = deviceError.data?.error;

      if (errorCode === 'authorization_pending') {
        // User hasn't authorized yet - continue polling
        await sleep(currentInterval * 1000);
        continue;
      }

      if (errorCode === 'slow_down') {
        // Server wants us to slow down - add 5 seconds to interval
        currentInterval += 5;
        await sleep(currentInterval * 1000);
        continue;
      }

      if (errorCode === 'access_denied') {
        throw new Error('User denied authorization');
      }

      if (errorCode === 'expired_token') {
        throw new Error(
          'Device code expired. Call initiateDeviceFlow() again.',
        );
      }

      // Unknown error
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error';
      throw new Error(
        `Failed to poll for device token for "${providerKey}": ${errorMessage}`,
      );
    }
  }
}

/**
 * Helper to sleep for a specified number of milliseconds
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Convenience function that combines initiateDeviceFlow and pollForDeviceToken
 *
 * This is a simplified API for CLI tools where you want to:
 * 1. Initiate the flow
 * 2. Display instructions
 * 3. Wait for authorization
 *
 * ### Example:
 * ```typescript
 * import { authenticateDevice } from '@milencode/h3-oauth-kit/device-flow';
 *
 * const tokens = await authenticateDevice('github', {
 *   scopes: ['repo', 'user'],
 *   onStart: (deviceAuth) => {
 *     console.log('Visit:', deviceAuth.verification_uri);
 *     console.log('Code:', deviceAuth.user_code);
 *   },
 *   onPoll: (attempt, seconds) => {
 *     console.log(`Waiting... (${seconds}s)`);
 *   },
 * });
 *
 * console.log('Authenticated!', tokens.access_token);
 * ```
 *
 * @param provider - The OAuth provider
 * @param options - Combined options for both initiate and poll
 * @returns A promise that resolves to the token response
 */
export async function authenticateDevice(
  provider: OAuthProvider,
  options: DeviceFlowOptions &
    DeviceTokenPollOptions & {
      onStart?: (deviceAuth: DeviceAuthorizationResponse) => void | Promise<void>;
    } = {},
): Promise<DeviceTokenResponse> {
  const { onStart, ...restOptions } = options;

  // Initiate device flow
  const deviceAuth = await initiateDeviceFlow(provider, restOptions);

  // Call onStart callback
  if (onStart) {
    await onStart(deviceAuth);
  }

  // Poll for token
  const tokens = await pollForDeviceToken(
    provider,
    deviceAuth.device_code,
    restOptions,
  );

  return tokens;
}

