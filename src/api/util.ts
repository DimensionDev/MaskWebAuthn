import { decode } from 'cbor-redux'
import type { AttestationObject, PublicKeyCredential } from '../types/interface'

export function concatenate(...arrays: (ArrayBuffer | Uint8Array)[]): ArrayBuffer {
    const buffersLengths = arrays.map((array) => array.byteLength)
    const totalLength = buffersLengths.reduce((p, c) => p + c, 0)
    const buffer = new Uint8Array(totalLength)
    buffersLengths.reduce(function (p, c, i) {
        const v = arrays[i]
        if (v instanceof ArrayBuffer) {
            buffer.set(new Uint8Array(v), p)
        } else {
            buffer.set(v, p)
        }
        return p + c
    }, 0)
    return buffer.buffer
}

export async function verify(publicKey: CryptoKey, credential: PublicKeyCredential): Promise<boolean> {
    const { clientDataJSON, attestationObject } = credential.response
    if (attestationObject) {
        const decodedAttestationObject = decode(attestationObject) as AttestationObject
        const {
            attStmt: { sig },
            authData,
        } = decodedAttestationObject
        const clientDataJsonHash = await crypto.subtle.digest('SHA-256', clientDataJSON)
        return crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256',
            },
            publicKey,
            sig,
            concatenate(authData, clientDataJsonHash),
        )
    }
    // fallback
    return Promise.resolve().then(() => true)
}
