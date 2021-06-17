import { decode } from 'cbor-redux'
import type { AttestationObject } from '../types/interface'

export async function verify (
  publicKey: CryptoKey,
  credential: PublicKeyCredential
): Promise<boolean> {
  const {
    clientDataJSON,
    attestationObject
  } = (credential.response as AuthenticatorAttestationResponse)
  if (clientDataJSON) {
    // JSON.parse(Buffer.from(clientDataJSON).toString('utf-8')) as CollectedClientData
  }
  if (attestationObject) {
    const decodedAttestationObject = decode(
      attestationObject) as AttestationObject
    const { attStmt: { sig: signature } } = decodedAttestationObject
    return crypto.subtle.verify({
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    publicKey,
    signature,
    attestationObject
    )
  }
  // fallback
  return Promise.resolve().then(() => true)
}
