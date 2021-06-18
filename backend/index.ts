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

  // sign count\
  getSignCount (key: CryptoKey): Promise<number>

  incrementSignCount (key: CryptoKey): Promise<void>

  hasCredential (options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Promise<boolean>

  // without username
  getResidentKeyPair (rpID: string): Promise<readonly [key: CryptoKeyPair, credentialID: ArrayBuffer]>

  // with username
  getKeyPairByKeyWrap (
    rpID: string,
    credentialIDs: BufferSource[],
  ): Promise<readonly [key: CryptoKeyPair | null, credentialID: ArrayBuffer]>
}

export function createPublicKeyAuthenticator (opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
  return {
    create: create.bind(undefined, opts),
    get: get.bind(undefined, opts)
  }
}
