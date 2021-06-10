// copy from: https://github.com/DimensionDev/Maskbook/blob/7390500ffe0c5de9beb04f8f9cf3e67841558554/packages/maskbook/src/utils/type-transform/CryptoKey-JsonWebKey.ts
import stableStringify from 'json-stable-stringify'
const CryptoKeyCache = new Map<string, CryptoKey>()
const JsonWebKeyCache = new WeakMap<CryptoKey, JsonWebKey>()

type Algorithms =
  | string
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | DhImportKeyParams
  | AesKeyAlgorithm

export function getKeyParameter (
  type: 'ecdh' | 'ecdsa' | 'aes' | 'pbkdf2',
): [readonly KeyUsage[], Readonly<Algorithms>] {
  if (type === 'ecdh') return [['deriveKey', 'deriveBits'], { name: 'ECDH', namedCurve: 'K-256' }]
  if (type === 'aes') return [['encrypt', 'decrypt'], { name: 'AES-GCM', length: 256 }]
  if (type === 'ecdsa') return [['sign', 'verify'], { name: 'ecdsa', namedCurve: 'K-256' }]
  throw new TypeError('Invalid key type')
}

/**
 * Get a (cached) CryptoKey from JsonWebKey
 *
 * JsonWebKeyToCryptoKey(key, ...getKeyParameter('aes'))
 *
 * @param algorithm - use which algorithm to import this key, defaults to ECDH K-256
 * @param key - The JsonWebKey
 * @param usage - Usage
 */
export async function JsonWebKeyToCryptoKey (
  key: JsonWebKey,
  usage: readonly KeyUsage[],
  algorithm: Algorithms,
): Promise<CryptoKey> {
  key = { ...key }
  // ? In some cases the raw JWK stores the usage of "decrypt" only so our full usage will throw an error
  const usages = [...usage].sort().join(',')
  if (key.key_ops) {
    if (key.key_ops.sort().join('.') !== usages) {
      key.key_ops = [...usage]
    }
  }
  const _key = stableStringify(key) + usages
  if (CryptoKeyCache.has(_key)) return CryptoKeyCache.get(_key)!
  const cryptoKey = await crypto.subtle.importKey('jwk', key, algorithm, true, [...usage])
  CryptoKeyCache.set(_key, cryptoKey)
  JsonWebKeyCache.set(cryptoKey, key)
  return cryptoKey
}

/**
 * Get a (cached) JsonWebKey from CryptoKey
 * @param key - The CryptoKey
 */
export async function CryptoKeyToJsonWebKey<T extends JsonWebKey = JsonWebKey> (key: CryptoKey): Promise<T> {
  // Any of nominal subtype of JsonWebKey in this project is runtime equivalent to JsonWebKey
  // so it is safe to do the force cast
  if (JsonWebKeyCache.has(key)) return JsonWebKeyCache.get(key)! as T
  const jwk = await crypto.subtle.exportKey('jwk', key)
  JsonWebKeyCache.set(key, jwk)
  const hash = stableStringify(jwk) + [...key.usages].sort().join(',')
  CryptoKeyCache.set(hash, key)
  return jwk as T
}

export const bufferSourceToBase64 = (buffer: BufferSource): string => {
  if (buffer instanceof ArrayBuffer) {
    return btoa(new Uint8Array(buffer).reduce(
      (str, cur) => str + String.fromCharCode(cur), ''))
  } else {
    return bufferSourceToBase64(buffer.buffer)
  }
}

export function isSecureContext (): boolean {
  if (global?.isSecureContext) {
    return true
  } else {
    // todo
    return true
  }
}

export function isRegistrableDomain (
  hostSuffixString: string, originalHost: string): boolean {
  // refs:
  //  https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to
  //  https://github.com/passwordless-lib/fido2-net-lib/blob/bdad59ec9963c45c07b4c50b95cc3209d763a91e/Src/Fido2/AuthenticatorResponse.cs#L58-L83
  const host = new URL(hostSuffixString)
  const origin = new URL(originalHost)
  if (host.host.startsWith('localhost') && origin.host.startsWith('localhost')) {
    // allow localhost
    return true
  } else if (['https:'].includes(host.protocol)) {
    // only support 'https' protocol
    return origin.host.endsWith(host.host)
  } else {
    return false
  }
}

export function securityCheck (): boolean {
  if (!isSecureContext()) {
    return false
  } else {
    // todo: check origin and domain
    return true
  }
}
