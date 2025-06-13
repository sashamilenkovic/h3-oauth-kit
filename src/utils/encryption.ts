const IV_LENGTH = 16;

const rawKey = process.env.H3_OAUTH_ENCRYPTION_KEY;

if (!rawKey || rawKey.length !== 64) {
  throw new Error(
    '[h3-oauth-kit] H3_OAUTH_ENCRYPTION_KEY must be a 64-character hex string (32 bytes).',
  );
}

// Convert hex string to Uint8Array
function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// Convert Uint8Array to hex string
function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

const ENCRYPTION_KEY_BYTES = hexToUint8Array(rawKey);

// Import the key for use with Web Crypto API
async function getEncryptionKey(): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    'raw',
    ENCRYPTION_KEY_BYTES,
    { name: 'AES-CBC' },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encrypt(text: string): Promise<string> {
  // Generate random IV
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  // Get the encryption key
  const key = await getEncryptionKey();

  // Encode text to bytes
  const textBytes = new TextEncoder().encode(text);

  // Encrypt the data
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv: iv,
    },
    key,
    textBytes,
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);

  // Return IV and encrypted data as hex strings separated by ':'
  return uint8ArrayToHex(iv) + ':' + uint8ArrayToHex(encryptedBytes);
}

export async function decrypt(encryptedText: string): Promise<string> {
  if (typeof encryptedText !== 'string') {
    throw new Error('Encrypted text must be a string');
  }

  const [ivHex, encryptedHex] = encryptedText.split(':');

  if (!ivHex || !encryptedHex) {
    throw new Error('Invalid encrypted text format');
  }

  // Convert hex strings back to Uint8Arrays
  const iv = hexToUint8Array(ivHex);
  if (iv.length !== IV_LENGTH) {
    throw new Error('Invalid IV length in encrypted text');
  }
  const encryptedBytes = hexToUint8Array(encryptedHex);

  // Get the decryption key
  const key = await getEncryptionKey();

  // Decrypt the data
  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv: iv,
    },
    key,
    encryptedBytes,
  );

  // Convert decrypted bytes back to string
  return new TextDecoder().decode(decryptedBuffer);
}
