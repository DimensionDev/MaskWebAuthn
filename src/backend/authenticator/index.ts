import { concatenate, encodeAuthData, serializeCollectedClientData, sha256 } from '../util'
import { encode } from 'cbor-redux'
import type { CollectedClientData, AttestationObject } from '../../types/interface'
import btoa from 'btoa'
import type { PublicKeyCredential } from '../../types/interface'
import { Alg } from '../../types/interface'

function getSignatureParams(alg: Alg): EcdsaParams {
    if (alg === Alg.ES256) {
        return {
            name: 'ECDSA',
            hash: { name: 'SHA-256' },
        }
    } else {
        throw new TypeError('Unsupported algorithm')
    }
}

const supportSet = new Set([Alg.ES256]) as ReadonlySet<Alg>

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

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', publicKey)
    const rpHostname: ArrayBuffer = Buffer.from(new URL(rpID).hostname, 'utf-8').buffer
    const rpHash = await sha256(rpHostname)

    const authData = encodeAuthData({
        rpIdHash: rpHash,
        flags: 0,
        signCount,
        attestedCredentialData: {
            aaugid: '0', // we not support aaguid
            credentialId,
            credentialPublicKey: publicKeyJwk,
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
        type: 'public-key',
        id: btoa(String.fromCharCode(...new Uint8Array(credentialId))),
        rawId: credentialId,
        response: {
            clientDataJSON: clientDataJsonBuffer,
            attestationObject,
        },
    }
}
