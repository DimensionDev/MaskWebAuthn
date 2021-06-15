import type { PublicKeyAuthenticatorProtocol } from '../types/interface'
import { create } from './publicKey'

export interface NormalizedCreateOptions {
  keys: CryptoKeyPair
  timeout: number
  rpID: string
  crossOrigin: boolean
}

export interface CreateAuthenticatorOptions {
  getNormalizedCreateOptions(): Promise<NormalizedCreateOptions>
  //
  getSignCount(key: JsonWebKey): Promise<number>
  incrementSignCount(key: JsonWebKey): Promise<void>
  hasKeyPairKeyWrap(credentialID: BufferSource[]): Promise<boolean>
  // without username
  getResidentKeyPair(rpID: string): Promise<CryptoKeyPair>
  // with username
  getKeyPairByKeyWrap(rpID: string, credentialID: BufferSource[]): Promise<CryptoKeyPair | null>
}

export function createPublicKeyAuthenticator (opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
  return {
    create: create.bind(undefined, opts),
  }
}
