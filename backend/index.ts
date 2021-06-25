import { create, get } from './publicKey'
import type { PublicKeyAuthenticatorProtocol } from '../types/interface'

export interface NormalizedCreateOptions {
    timeout: number
    rpID: string
    challenge: BufferSource
    crossOrigin: boolean
}

export interface CreateAuthenticatorOptions {
    getNormalizedCreateOptions(): Promise<NormalizedCreateOptions>

    // sign count
    getSignCount(key: CryptoKey, rpID: string, credentialID: ArrayBuffer): Promise<number>

    incrementSignCount(key: CryptoKey, rpID: string, credentialID?: ArrayBuffer | null): Promise<void>

    hasCredential(rpID: string, credentialID: ArrayBuffer): Promise<boolean>

    // without username
    getResidentKeyPair(rpID: string): Promise<readonly [key: CryptoKeyPair, credentialID: ArrayBuffer]>

    // with username
    getKeyPairByKeyWrap(
        rpID: string,
        credentialIDs: BufferSource[],
    ): Promise<readonly [key: CryptoKeyPair | null, credentialID: ArrayBuffer]>
}

export function createPublicKeyAuthenticator(opts: CreateAuthenticatorOptions): PublicKeyAuthenticatorProtocol {
    return {
        create: create.bind(undefined, opts),
        get: get.bind(undefined, opts),
    }
}
