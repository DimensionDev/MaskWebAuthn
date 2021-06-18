import { Buffer } from 'buffer'
import type { CollectedClientData } from '../dist/types/interface'

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

export const checkUserVerification = (userVerification: UserVerificationRequirement): boolean => {
  switch (userVerification) {
    case 'discouraged':
      return false
    case 'preferred':
    case 'required':
    default:
      return true
  }
}

export const filterCredentials = (credentials: PublicKeyCredentialDescriptor[]): PublicKeyCredentialDescriptor[] =>
  credentials.filter(
    credential => {
      if (credential.transports &&
        Array.isArray(credential.transports) &&
        credential.transports.length > 0) {
        return false
      } else {
        return credential.type === 'public-key'
      }
    }
  )

export function serializeCollectedClientData (collectedClientData: CollectedClientData): string {
  let result = ''
  result += '{'
  result += '"type":'
  result += ccdToString(collectedClientData.type)
  result += ',"challenge":{'
  result += '"type":"Buffer",'
  result += '"data":['
  result += ccdToString(collectedClientData.challenge).slice(1, -1)
  result += ']}'
  result += ',"origin":'
  result += ccdToString(collectedClientData.origin)
  result += ',"crossOrigin":'
  result += collectedClientData.crossOrigin ? 'true' : 'false'
  // we dont handle the rest of the client data
  result += '}'
  return result
}

/**
 * @link https://www.w3.org/TR/webauthn-3/#ccdtostring
 */
export function ccdToString (obj: any) {
  let encoded = ''
  encoded += '"'
  const objString = `${obj}`
  // warning: not support IE 11
  for (const char of objString) {
    // check whether char is UTF-16 text
    // if `char.length > 1`, then it is the UTF-16
    const charCode: number = char.length > 1
      ? parseInt(
        char.charCodeAt(0).toString(16) + char.charCodeAt(1).toString(16), 16)
      : char.charCodeAt(0)
    // 0x20 space
    // 0x21 !
    // 0x22 "
    // 0x5c \
    if (charCode === 0x0020 || charCode === 0x0021 ||
      (charCode >= 0x0023 && charCode <= 0x005b) ||
      (charCode >= 0x005d && charCode <= 0x10ffff)) {
      encoded += char
    } else if (charCode === 0x22) {
      encoded += String.fromCharCode(0x5c, 0x22) // \"
    } else if (charCode === 0x5c) {
      encoded += String.fromCharCode(0x5c, 0x5c) // \\
    } else {
      encoded += '\\u' + charCode.toString(16) // \uxxxx
    }
  }
  encoded += '"'
  return encoded
}

export async function sha256 (message: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', message)
}

export enum AuthDataFlag {
  ED = 1 << 7,
  AT = 1 << 6,
  UV = 1 << 2,
  UP = 1 << 0
}

export type AuthData = {
  rpIdHash: string // sha256 encrypted replying party id
  flags: AuthDataFlag
  signCount: number
  attestedCredentialData: {
    aaugid: string // is zero
    credentialId: ArrayBuffer
    credentialPublicKey: ArrayBuffer
  }
  extensions: unknown // not support yet
}

export function concatenate (...arrays: ArrayBuffer[]): ArrayBuffer {
  const buffersLengths = arrays.map(function (b) { return b.byteLength })
  const totalLength = buffersLengths.reduce((p, c) => p + c, 0)
  const buffer = Buffer.alloc(totalLength)
  buffersLengths.reduce(function (p, c, i) {
    buffer.set(Buffer.from(arrays[i]), p)
    return p + c
  }, 0)
  return buffer.buffer
}

export function encodeAuthData (authData: AuthData): ArrayBuffer {
  // set idHash, 32 byte
  const idHashBuffer = Buffer.from(authData.rpIdHash)
  // set flags, 1 byte
  const flagsBuffer = new Uint8Array(1)
  flagsBuffer.set([authData.flags], 0)
  // set signCount, 4 byte
  const signCountBuffer = new Uint32Array(1)
  signCountBuffer.set([authData.signCount], 0)
  // set attestedCredentialData
  const { credentialId, credentialPublicKey } = authData.attestedCredentialData
  const aaguidBuffer = new Uint32Array(4).fill(0) // is zero
  const credentialIdLengthBuffer = new Uint16Array(1)
  credentialIdLengthBuffer.set([credentialId.byteLength], 0)
  return concatenate(
    idHashBuffer.buffer,
    flagsBuffer.buffer,
    signCountBuffer.buffer,
    aaguidBuffer.buffer,
    credentialIdLengthBuffer.buffer,
    credentialId,
    credentialPublicKey
  )
}
