import type { PublicKeyAuthenticatorProtocol } from '../types/interface'
import { create } from './publicKey'
import { get } from './publicKey/get'

export interface NormalizedCreateOptions {
  keys: CryptoKeyPair
  timeout: number
  rpID: string
  challenge: BufferSource
  crossOrigin: boolean
}

export interface CreateAuthenticatorOptions {
  getNormalizedCreateOptions (): Promise<NormalizedCreateOptions>

  // sign count
  getSignCount (key: JsonWebKey): Promise<number>

  incrementSignCount (key: JsonWebKey): Promise<void>

  hasCredential (options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Promise<boolean>

  hasKeyPairKeyWrap (credentialID: BufferSource[]): Promise<boolean>

  // without username
  getResidentKeyPair (rpID: string): Promise<CryptoKeyPair>

  // with username
  getKeyPairByKeyWrap (
    rpID: string, credentialID: BufferSource[]): Promise<CryptoKeyPair | null>
}

export function createPublicKeyAuthenticator (opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
  return {
    create: create.bind(undefined, opts),
    get: get.bind(undefined, opts)
  }
}
