import { create, get } from './publicKey'
import type { PublicKeyAuthenticatorProtocol } from '../types/interface'

export interface CreateAuthenticatorOptions {
    // sign count
    getSignCount(key: CryptoKey, rpID: string, credentialID: ArrayBuffer): Promise<number>
    incrementSignCount(key: CryptoKey, rpID: string, credentialID: ArrayBuffer): Promise<void>

    // without username
    getResidentKeyPair(rpID: string): Promise<readonly [key: CryptoKeyPair, credentialID: ArrayBuffer]>

    // get key from existing credential
    createKeyPairByKeyWrap(
        rpID: string,
        excludeCredentialIDs: ArrayBuffer[],
    ): Promise<readonly [key: CryptoKeyPair, credentialID: ArrayBuffer]>

    getKeyPairByKeyWrap(
        rpID: string,
        candidateCredentialIDs: ArrayBuffer[],
    ): Promise<readonly [key: CryptoKeyPair | null, credentialID: ArrayBuffer]>
}

export function createPublicKeyAuthenticator(opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
    return {
        create: create.bind(undefined, opts),
        get: get.bind(undefined, opts),
    }
}
