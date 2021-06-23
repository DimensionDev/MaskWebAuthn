import { decode } from 'cbor-redux'
import type { AttestationObject } from '../types/interface'
import { Buffer } from 'buffer'

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

export async function verify (
  publicKey: CryptoKey,
  credential: PublicKeyCredential
): Promise<boolean> {
  const {
    clientDataJSON,
    attestationObject
  } = (credential.response as AuthenticatorAttestationResponse)
  if (attestationObject) {
    const decodedAttestationObject = decode(
      attestationObject) as AttestationObject
    const { attStmt: { sig }, antData } = decodedAttestationObject
    const clientDataJsonHash = await crypto.subtle.digest('SHA-256', clientDataJSON)
    return crypto.subtle.verify({
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    publicKey,
    sig,
    concatenate(antData, clientDataJsonHash)
    )
  }
  // fallback
  return Promise.resolve().then(() => true)
}
