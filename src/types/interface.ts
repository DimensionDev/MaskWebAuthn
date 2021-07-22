// see RFC-8152 section 13, Table 21
export enum Kty {
    OKP = 1,
    EC = 2,
    RSA = 3,
    Symmetric = 4,
    Reserved = 0,
}

// see key in RFC-7518 3.1
// see ECDSA in RFC-8152 8.1, Table 5
export enum Alg {
    'ES256' = -7,
    'ES384' = -35,
    'ES512' = -36,
}

// see RFC-8152 section 13.1, Table 22
export enum Crv {
    'P-256' = 1,
    'P-384' = 2,
    'P-521' = 3,
}

// see RFC-8152 section 7.1
export enum CoseKey {
    kty = 1,
    crv = -1,
    alg = 3,
    x = -2,
    y = -3,
    d = -4,
}

export interface EcCosePublicKey {
    [CoseKey.kty]: Kty
    [CoseKey.alg]: Alg
    [CoseKey.crv]: Crv
    [CoseKey.x]: string
    [CoseKey.y]: string
}

export interface EcCosePrivateKey extends EcCosePublicKey {
    [CoseKey.d]: string
}

export interface PublicKeyCredential extends Credential {
    readonly rawId: ArrayBuffer
    readonly response: AuthenticatorAttestationResponse
}

export interface PublicKeyAuthenticatorProtocol {
    create(options: PublicKeyCredentialCreationOptions, signal?: AbortSignal): Promise<PublicKeyCredential | null>
    get(options: PublicKeyCredentialRequestOptions, signal?: AbortSignal): Promise<PublicKeyCredential | null>
}
export interface _FederatedAuthenticatorProtocol {}
export interface _PasswordAuthenticatorProtocol {}

export type CollectedClientData = {
    type: 'webauthn.create' | 'webauthn.get'
    challenge: string
    origin: string
    crossOrigin: boolean
    tokenBinding: unknown
}

export type AttestationObject = {
    fmt: string
    attStmt: {
        alg: number
        sig: ArrayBuffer
    }
    authData: ArrayBuffer
}
