import {
  bufferSourceToBase64, encodeAuthData, sha256,
} from '../util'
import type { CollectedClientData } from '../'
import { Buffer } from 'buffer'
import { encode } from 'cbor-redux'

export enum PublicKeyAlgorithm {
  ES256 = -7
}

export function getSignatureParams (alg: PublicKeyAlgorithm): EcdsaParams | RsaPssParams {
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

// todo: this is incorrect
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
    rpIdHash: await sha256(rpID),
    flags: 0,
    signCount,
    attestedCredentialData: {
      aaugid: '0',
      credentialIdLength: 0,
      credentialId: '',
      credentialPublicKey: await crypto.subtle.exportKey('raw', keys.publicKey),
    },
    extensions: undefined,
  })
  const signType = algs.find(alg => supportSet.has(alg))
  if(!signType) {
    throw new Error('Not Support Algorithm')
  }
  const signParams = getSignatureParams(signType)
  const signature = await crypto.subtle.sign(signParams, keys.privateKey,
    antData)

  const attestationObject = encode({
    fmt: 'packed',
    attStmt: {
      alg: signType,
      sig: signature,
    },
    antData,
  })

  // fixme: json key order
  const clientDataJSON = Buffer.from(JSON.stringify({
    challenge: clientData.challenge,  // relying party will check the challenge
    origin: clientData.origin,  // 'https://xxx.xx'
    type: clientData.type, // 'webauthn.create'
  }))

  return {
    id: base64ID,
    rawId,
    response: {
      clientDataJSON,
      attestationObject,
    } as AuthenticatorAttestationResponse,
    type: 'public-key',
    getClientExtensionResults (): AuthenticationExtensionsClientOutputs {
      throw new Error('not supported')
    },
  }
}

