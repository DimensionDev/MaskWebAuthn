import {
  concatenate,
  encodeAuthData,
  serializeCollectedClientData,
  sha256
} from '../util'
import { Buffer } from 'buffer'
import { encode } from 'cbor-redux'
import type { CollectedClientData, AttestationObject } from '../../types/interface'

export enum PublicKeyAlgorithm {
  ES256 = -7
}

export function getSignatureParams (alg: PublicKeyAlgorithm): EcdsaParams {
  if (alg === PublicKeyAlgorithm.ES256) {
    return {
      name: 'ECDSA',
      hash: 'SHA-256'
    }
  } else {
    throw new TypeError('')
  }
}

const supportSet = new Set([PublicKeyAlgorithm.ES256])

export async function generateCreationResponse (
  // maskbook provided
  credentialId: ArrayBuffer,
  keys: CryptoKeyPair,
  signCount: number,
  // user provided
  rpID: string,
  clientData: CollectedClientData,
  algs: number[],
  // other options
  signal?: AbortSignal
): Promise<PublicKeyCredential> {
  const { publicKey, privateKey } = keys

  if (signal?.aborted) {
    throw new DOMException('AbortError')
  }

  const rawPublicKey = await crypto.subtle.exportKey('raw', publicKey)
  const idBuffer = Buffer.from(rawPublicKey)

  const antData = encodeAuthData({
    rpIdHash: Buffer.from(await sha256(Buffer.from(rpID, 'utf-8'))).toString('utf-8'),
    flags: 0,
    signCount,
    attestedCredentialData: {
      aaugid: '0', // we not support aaguid
      credentialId,
      credentialPublicKey: await crypto.subtle.exportKey('raw', publicKey)
    },
    extensions: undefined
  })

  const clientDataJson = serializeCollectedClientData({ ...clientData })
  const clientDataJsonBuffer = Buffer.from(clientDataJson)
  const clientDataJsonHash = await sha256(clientDataJsonBuffer)

  // start sign
  const signType = algs.find(alg => supportSet.has(alg))
  if (!signType) {
    throw new Error('Not Support Algorithm')
  }
  const signParams = getSignatureParams(signType)
  const signTarget = concatenate(antData, clientDataJsonHash)
  const signature = await crypto.subtle.sign(signParams, privateKey, signTarget)
  // end sign

  const attestationObject = encode({
    fmt: 'packed',
    attStmt: {
      alg: signType,
      sig: signature
    },
    antData
  } as AttestationObject)

  return {
    id: idBuffer.toString('base64'),
    rawId: idBuffer.buffer,
    response: {
      clientDataJSON: clientDataJsonBuffer,
      attestationObject
    } as AuthenticatorAttestationResponse,
    type: 'public-key',
    getClientExtensionResults (): AuthenticationExtensionsClientOutputs {
      throw new Error('not supported')
    }
  }
}
