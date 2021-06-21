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
    getSignCount(key: CryptoKey): Promise<number>

    incrementSignCount(key: CryptoKey): Promise<void>

    hasCredential(options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Promise<boolean>

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
        create: function () {
            throw new Error()
        },
        get: function () {
            throw new Error()
        },
    }
}
