export const bufferSourceToBase64 = (buffer: BufferSource): string => {
  if (buffer instanceof ArrayBuffer) {
    return btoa(new Uint8Array(buffer).reduce(
      (str, cur) => str + String.fromCharCode(cur), ''))
  } else {
    return bufferSourceToBase64(buffer.buffer)
  }
}

export function isRegistrableDomain (
  hostSuffixString: string, originalHost: string): boolean {
  // refs:
  //  https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to
  //  https://github.com/passwordless-lib/fido2-net-lib/blob/bdad59ec9963c45c07b4c50b95cc3209d763a91e/Src/Fido2/AuthenticatorResponse.cs#L58-L83
  if (hostSuffixString === '' && originalHost === '') {
    return false
  }
  let host: string = ''
  let origin: string = ''
  try {
    const url = new URL(hostSuffixString)
    if (url.protocol !== 'https:') {
      return false
    }
    host = url.host
  } catch (_) {
    host = hostSuffixString
  }
  try {
    const url = new URL(originalHost)
    if (url.protocol !== 'https:') {
      return false
    }
    origin = url.host
  } catch (_) {
    origin = originalHost
  }

  if (origin.startsWith('localhost')) {
    // allow localhost
    return true
  } else {
    return host.endsWith(origin)
  }
}

export async function sha256 (message: string) {
  const messageBuffer = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('SHA-256', messageBuffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('')
}

export enum AuthDataFlag {
  ED = 1 << 7,
  AT = 1 << 6,
  UV = 1 << 2,
  UP = 1 << 0
}

export type AuthData = {
  rpIdHash: string  // sha256 encrypted replying party id
  flags: AuthDataFlag
  signCount: number
  attestedCredentialData: {
    aaugid: string  // is zero
    credentialIdLength: number
    credentialId: string
    credentialPublicKey: string
  }
  extensions: unknown // not support yet
}

export function concatenate (...arrays: ArrayBuffer[]): ArrayBuffer {
  const buffersLengths = arrays.map(function (b) { return b.byteLength })
  const totalLength = buffersLengths.reduce((p, c) => p + c, 0)
  const unit8Arr = new Uint8Array(totalLength)
  buffersLengths.reduce(function (p, c, i) {
    unit8Arr.set(new Uint8Array(arrays[i]), p)
    return p + c
  }, 0)
  return unit8Arr.buffer
}

export function encodeAuthData (authData: AuthData): ArrayBuffer {
  const textEncoder = new TextEncoder()
  // set idHash, 32 byte
  const idHashBuffer = textEncoder.encode(authData.rpIdHash)
  // set flags, 1 byte
  const flagsBuffer = new Uint8Array(1)
  flagsBuffer.set([authData.flags], 1)
  // set signCount, 4 byte
  const signCountBuffer = new Uint32Array(1)
  signCountBuffer.set([authData.signCount], 0)
  // set attestedCredentialData
  const { credentialIdLength } = authData.attestedCredentialData
  const aaguidBuffer = new Uint32Array(4).fill(0) // is zero
  const credentialIdLengthBuffer = new Uint16Array(1)
  credentialIdLengthBuffer.set([credentialIdLength], 0)
  const credentialPublicKeyBuffer = textEncoder.encode(
    authData.attestedCredentialData.credentialPublicKey)
  return concatenate(idHashBuffer.buffer, flagsBuffer.buffer,
    signCountBuffer.buffer, aaguidBuffer.buffer,
    credentialIdLengthBuffer.buffer, credentialPublicKeyBuffer.buffer)
}
