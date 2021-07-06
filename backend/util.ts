import { Buffer } from 'buffer'
import type { CollectedClientData } from '../types/interface'
import { encode } from 'cbor-redux'

export function isRegistrableDomain(hostSuffixString: string, originalHost: string): boolean {
    // refs:
    //  https://html.spec.whatwg.org/multipage/origin.html#is-a-registrable-domain-suffix-of-or-is-equal-to
    //  https://github.com/passwordless-lib/fido2-net-lib/blob/bdad59ec9963c45c07b4c50b95cc3209d763a91e/Src/Fido2/AuthenticatorResponse.cs#L58-L83
    if (hostSuffixString === '' && originalHost === '') {
        return false
    }
    let host: string = ''
    let origin: string = ''
    try {
        const url = new URL(hostSuffixString)
        if (url.protocol !== 'https:') {
            return false
        }
        host = url.host
    } catch (_) {
        host = hostSuffixString
    }
    try {
        const url = new URL(originalHost)
        if (url.protocol !== 'https:') {
            return false
        }
        origin = url.host
    } catch (_) {
        origin = originalHost
    }

    if (origin.startsWith('localhost')) {
        // allow localhost
        return true
    } else {
        return host.endsWith(origin)
    }
}

export function checkUserVerification(userVerification: UserVerificationRequirement): boolean {
    switch (userVerification) {
        case 'discouraged':
            return false
        case 'preferred':
        case 'required':
        default:
            return true
    }
}

export function filterCredentials(credentials: PublicKeyCredentialDescriptor[]): PublicKeyCredentialDescriptor[] {
    return credentials.filter((credential) => {
        if (credential.transports && Array.isArray(credential.transports) && credential.transports.length > 0) {
            return false
        } else {
            return credential.type === 'public-key'
        }
    })
}

export function serializeCollectedClientData(collectedClientData: CollectedClientData): string {
    let result = ''
    result += '{'
    result += '"type":'
    result += ccdToString(collectedClientData.type)
    result += ',"challenge":'
    result += ccdToString(collectedClientData.challenge)
    result += ',"origin":'
    result += ccdToString(collectedClientData.origin)
    result += ',"crossOrigin":'
    result += collectedClientData.crossOrigin ? 'true' : 'false'
    // we don't handle the rest of the client data
    result += '}'
    return result
}

/**
 * @link https://www.w3.org/TR/webauthn-3/#ccdtostring
 */
export function ccdToString(obj: any) {
    let encoded = ''
    encoded += '"'
    const objString = `${obj}`
    for (const char of objString) {
        // check whether char is UTF-16 text
        // if `char.length > 1`, then it is the UTF-16
        const charCode: number =
            char.length > 1
                ? parseInt(char.charCodeAt(0).toString(16) + char.charCodeAt(1).toString(16), 16)
                : char.charCodeAt(0)
        // 0x20 space
        // 0x21 !
        // 0x22 "
        // 0x5c \
        if (
            charCode === 0x0020 ||
            charCode === 0x0021 ||
            (charCode >= 0x0023 && charCode <= 0x005b) ||
            (charCode >= 0x005d && charCode <= 0x10ffff)
        ) {
            encoded += char
        } else if (charCode === 0x22) {
            encoded += String.fromCharCode(0x5c, 0x22) // \"
        } else if (charCode === 0x5c) {
            encoded += String.fromCharCode(0x5c, 0x5c) // \\
        } else {
            encoded += '\\u' + charCode.toString(16) // \uxxxx
        }
    }
    encoded += '"'
    return encoded
}

export async function sha256(message: ArrayBuffer): Promise<ArrayBuffer> {
    return crypto.subtle.digest('SHA-256', message)
}

export enum AuthDataFlag {
    ED = 1 << 7,
    AT = 1 << 6,
    UV = 1 << 2,
    UP = 1 << 0,
}

export type AuthData = {
    rpIdHash: ArrayBuffer // sha256 hashed replying party id
    flags: AuthDataFlag
    signCount: number
    attestedCredentialData: {
        aaugid: string // is zero
        credentialId: ArrayBuffer
        credentialPublicKey: JsonWebKey
    }
    extensions: unknown // not support yet
}

export function concatenate(...arrays: ArrayBuffer[]): ArrayBuffer {
    const buffersLengths = arrays.map(function (b) {
        return b.byteLength
    })
    const totalLength = buffersLengths.reduce((p, c) => p + c, 0)
    const buffer = Buffer.alloc(totalLength)
    buffersLengths.reduce(function (p, c, i) {
        buffer.set(Buffer.from(arrays[i]), p)
        return p + c
    }, 0)
    return buffer.buffer
}

export function jwkToCOSEKey(jwk: JsonWebKey): ArrayBuffer {
    // todo: currently we only support ecdh p-256 algorithm
    const array: Buffer[] = []
    array.push(Buffer.from([0xa5])) // size 5 of map
    array.push(Buffer.from([0x01])) // key: kty
    array.push(Buffer.from([0x02])) // value: EC
    array.push(Buffer.from([0x20])) // key: crv
    array.push(Buffer.from([0x01])) // value: P-256
    array.push(Buffer.from([0x03])) // key: alg
    array.push(Buffer.from([0x26])) // value: -7
    array.push(Buffer.from(encode(-2))) // key: x
    array.push(Buffer.from(encode(jwk.x)))
    array.push(Buffer.from(encode(-3))) // key: y
    array.push(Buffer.from(encode(jwk.y)))
    return Buffer.concat(array)
}

export function encodeAuthData(authData: AuthData): ArrayBuffer {
    // set idHash, 32 byte
    if (authData.rpIdHash.byteLength !== 32) {
        throw new TypeError('length of rpIdHash must be 32.')
    }
    // set flags, 1 byte
    const flagsBuffer = new Uint8Array(1)
    flagsBuffer.set([authData.flags | AuthDataFlag.AT | AuthDataFlag.UV], 0)
    // set signCount, 4 byte
    const signCountBuffer = new Uint32Array(1)
    let view = new DataView(signCountBuffer.buffer)
    view.setUint32(0, authData.signCount, false)
    // set attestedCredentialData
    const { credentialId, credentialPublicKey } = authData.attestedCredentialData
    const aaguidBuffer = new Uint32Array(4).fill(0) // is zero
    const credentialIdLengthBuffer = new Uint16Array(1)
    view = new DataView(credentialIdLengthBuffer.buffer)
    view.setUint16(0, credentialId.byteLength, false)
    const publicKeyBuffer = jwkToCOSEKey(credentialPublicKey)
    return concatenate(
        authData.rpIdHash,
        flagsBuffer.buffer,
        signCountBuffer.buffer,
        aaguidBuffer.buffer,
        credentialIdLengthBuffer.buffer,
        credentialId,
        publicKeyBuffer,
    )
}
