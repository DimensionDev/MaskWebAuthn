import {
  arrayBufferToString,
  bufferSourceToBase64,
  concatenate,
  encodeAuthData,
  serializeCollectedClientData,
  sha256,
} from '../util'
import { Buffer } from 'buffer'
import { encode } from 'cbor-redux'
import type { CollectedClientData } from '../../types/interface'

export enum PublicKeyAlgorithm {
  ES256 = -7
}

export function getSignatureParams (alg: PublicKeyAlgorithm): EcdsaParams {
  if (alg === PublicKeyAlgorithm.ES256) {
    return {
      name: 'ECDSA',
      hash: 'SHA-256',
    }
  } else {
    throw new TypeError('')
  }
}

const supportSet = new Set([PublicKeyAlgorithm.ES256])

export async function generateCreationResponse (
  // maskbook provided
  keys: CryptoKeyPair,
  signCount: number,
  // user provided
  rpID: string,
  clientData: CollectedClientData,
  algs: number[],
  // other options
  signal?: AbortSignal,
): Promise<PublicKeyCredential> {
  if (!keys) {
    throw new TypeError()
  }
  const { publicKey } = keys

  if (signal?.aborted) {
    throw new DOMException('AbortError')
  }

  // id includes username and email, then it will save to the local database as the unique key
  const id = JSON.stringify(publicKey)
  const rawId = Buffer.from(id)
  const base64ID = bufferSourceToBase64(rawId)

  const antData = encodeAuthData({
    rpIdHash: arrayBufferToString(await sha256(rpID)),
    flags: 0,
    signCount,
    attestedCredentialData: {
      aaugid: '0',  // we not support aaguid
      credentialIdLength: 0,
      credentialId: '',
      credentialPublicKey: await crypto.subtle.exportKey('raw', keys.publicKey),
    },
    extensions: undefined,
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
  const signature = await crypto.subtle.sign(signParams, keys.privateKey,
    signTarget)
  // end sign

  const attestationObject = encode({
    fmt: 'packed',
    attStmt: {
      alg: signType,
      sig: signature,
    },
    antData,
  })

  return {
    id: base64ID,
    rawId,
    response: {
      clientDataJSON: clientDataJsonBuffer,
      attestationObject,
    } as AuthenticatorAttestationResponse,
    type: 'public-key',
    getClientExtensionResults (): AuthenticationExtensionsClientOutputs {
      throw new Error('not supported')
    },
  }
}

