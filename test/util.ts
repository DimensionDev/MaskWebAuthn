import NodeCrypto from 'crypto'
import { decode } from 'cbor-redux'
import type { PublicKeyCredential } from '../types/interface'
import type { EcCosePublicKey } from '../types/interface'
import { Alg, CoseKey, Crv, Kty } from '../types/interface'
import { sha256 } from '../backend/util'

export const parseAuthData = (buffer: Buffer) => {
    let rpIdHash = buffer.slice(0, 32)
    buffer = buffer.slice(32)
    let flagsBuf = buffer.slice(0, 1)
    buffer = buffer.slice(1)
    let flagsInt = flagsBuf[0]
    let flags = {
        up: !!(flagsInt & 0x01),
        uv: !!(flagsInt & 0x04),
        at: !!(flagsInt & 0x40),
        ed: !!(flagsInt & 0x80),
        flagsInt,
    }

    let counterBuf = Buffer.from(buffer.slice(0, 4))
    buffer = buffer.slice(4)
    let counter = counterBuf.readUInt32BE(0)

    let aaguid = undefined
    let credID = undefined
    let COSEPublicKey = undefined

    if (flags.at) {
        aaguid = buffer.slice(0, 16)
        buffer = buffer.slice(16)
        let credIDLenBuf = Buffer.from(buffer.slice(0, 2))
        buffer = buffer.slice(2)
        let credIDLen = credIDLenBuf.readUInt16BE(0)
        credID = buffer.slice(0, credIDLen)
        buffer = buffer.slice(credIDLen)
        COSEPublicKey = buffer
    }

    return { rpIdHash, flagsBuf, flags, counter, counterBuf, aaguid, credID, COSEPublicKey }
}

export async function cryptoKeyToPem(key: CryptoKey) {
    const type = key.type.toUpperCase()
    let out = ''
    let str = Buffer.from(await crypto.subtle.exportKey('spki', key)).toString('base64')
    out += `-----BEGIN ${type} KEY-----\n`
    while (str.length > 0) {
        out += str.substring(0, 64) + '\n'
        str = str.substring(64)
    }
    out += `-----END ${type} KEY-----`
    return out
}

export function hex2arrayBuffer(data: string): ArrayBuffer {
    const length = data.length / 2
    let ret = new Uint8Array(length)

    for (let i = 0; i < length; i += 1) {
        ret[i] = parseInt(data.substr(i * 2, 2), 16)
    }

    return ret.buffer
}

export const verifyPackedAttestation = async (keys: CryptoKeyPair, webAuthnResponse: PublicKeyCredential) => {
    const attestationBuffer = Buffer.from(webAuthnResponse.response.attestationObject)
    const attestationStruct = decode(attestationBuffer.buffer)

    const authDataStruct = parseAuthData(attestationStruct.authData)

    const clientDataJSONBuffer = Buffer.from(webAuthnResponse.response.clientDataJSON)
    const clientDataHash = Buffer.from(await sha256(clientDataJSONBuffer))
    const originalDataBuffer = Buffer.concat([attestationStruct.authData, clientDataHash])

    const signatureBuffer = attestationStruct.attStmt.sig
    let signatureIsValid = false

    if (!authDataStruct.COSEPublicKey) {
        throw new TypeError('COSE Public Key not found')
    }

    let publicKeyCose = decode(authDataStruct.COSEPublicKey.buffer) as EcCosePublicKey
    const alg = Alg[publicKeyCose[CoseKey.alg]]
    if (publicKeyCose[CoseKey.kty] === Kty.EC) {
        const x = publicKeyCose[CoseKey.x]
        const y = publicKeyCose[CoseKey.y]
        const crv = Crv[publicKeyCose[CoseKey.crv]]
        const kty = Kty[publicKeyCose[CoseKey.kty]]

        // start verify
        const publicKey = NodeCrypto.createPublicKey({
            format: 'jwk',
            key: {
                x,
                y,
                crv,
                kty,
                alg,
            },
        })

        // todo: refactor this to node implementation
        signatureIsValid = await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256',
            },
            keys.publicKey,
            signatureBuffer,
            originalDataBuffer,
        )
    }

    if (!signatureIsValid) throw new Error('Failed to verify the signature!')

    return true
}
