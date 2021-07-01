import { concatenate, encodeAuthData, serializeCollectedClientData, sha256 } from '../util'
import { Buffer } from 'buffer'
import { encode } from 'cbor-redux'
import type { CollectedClientData, AttestationObject } from '../../types/interface'

export enum PublicKeyAlgorithm {
    ES256 = -7,
}

function getSignatureParams(alg: PublicKeyAlgorithm): EcdsaParams {
    if (alg === PublicKeyAlgorithm.ES256) {
        return {
            name: 'ECDSA',
            hash: 'SHA-256',
        }
    } else {
        throw new TypeError('Unsupported algorithm')
    }
}

const supportSet = new Set([PublicKeyAlgorithm.ES256])

export async function generateCreationResponse(
    // backend creator provided
    credentialId: ArrayBuffer,
    keys: CryptoKeyPair,
    signCount: number,
    // RP provided
    rpID: string,
    clientData: CollectedClientData,
    algs: number[],
    signal?: AbortSignal,
): Promise<PublicKeyCredential> {
    const { publicKey, privateKey } = keys

    if (signal?.aborted) {
        throw new DOMException('AbortError')
    }

    const rawPublicKey = await crypto.subtle.exportKey('raw', publicKey)
    const idBuffer = Buffer.from(rawPublicKey)

    const authData = encodeAuthData({
        rpIdHash: await sha256(Buffer.from(rpID, 'utf-8')),
        flags: 0,
        signCount,
        attestedCredentialData: {
            aaugid: '0', // we not support aaguid
            credentialId,
            credentialPublicKey: await crypto.subtle.exportKey('jwk', publicKey),
        },
        extensions: undefined,
    })

    const clientDataJson = serializeCollectedClientData({ ...clientData })
    const clientDataJsonBuffer = Buffer.from(clientDataJson)
    const clientDataJsonHash = await sha256(clientDataJsonBuffer)

    // start sign
    const signType = algs.find((alg) => supportSet.has(alg))
    if (!signType) {
        throw new Error('Unsupported algorithm')
    }
    const signParams = getSignatureParams(signType)
    const signTarget = concatenate(authData, clientDataJsonHash)
    const signature = await crypto.subtle.sign(signParams, privateKey, signTarget)
    // end sign

    const obj = {
        fmt: 'packed',
        attStmt: {
            alg: signType,
            sig: signature,
        },
        authData,
    }
    const attestationObject = encode<AttestationObject>(obj)

    return {
        id: idBuffer.toString('base64'),
        rawId: idBuffer.buffer,
        response: {
            clientDataJSON: clientDataJsonBuffer,
            attestationObject,
        } as AuthenticatorAttestationResponse,
        type: 'public-key',
        getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
            return {}
        },
    }
}
