import type { PublicKeyAuthenticatorProtocol } from '../types/interface'
import { securityCheck } from './util'
import { create } from './publicKey'

function wrapSecurityCheck<T extends Function> (fn: T): T {
  securityCheck()
  return fn()
}

export interface CreateAuthenticatorOptions {
  privateKey: JsonWebKey
  publicKey: JsonWebKey
}

export function createPublicKeyAuthenticator (opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
  const { privateKey, publicKey } = opts

  return {
    create: wrapSecurityCheck(create.bind(undefined, privateKey, publicKey)),
  }
}
