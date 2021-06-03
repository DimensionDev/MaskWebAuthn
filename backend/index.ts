import type { PublicKeyAuthenticatorProtocol } from '../types/interface'
import { create } from './publicKey'

export interface CreateAuthenticatorOptions {
  privateKey: JsonWebKey
  publicKey: JsonWebKey
}

export function createPublicKeyAuthenticator (opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
  const { privateKey, publicKey } = opts
  const abortController = new AbortController()
  const abortSignal = abortController.signal

  return {
    // todo
    create: create.bind(undefined, privateKey, publicKey),
    signal: abortSignal,
    abort: () => abortController.abort(),
  }
}
