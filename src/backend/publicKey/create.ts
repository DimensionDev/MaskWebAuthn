import { generateCreationResponse } from '../authenticator'
import type { CreateAuthenticatorOptions } from '../index'
import { checkUserVerification, filterCredentials, normalizeCreateOption } from '../util'
import type { CollectedClientData, PublicKeyCredential } from '../../types/interface'
import { Alg } from '../../types/interface'
import { bytesToBase64 } from '../util/base64'

/**
 *
 * https://w3c.github.io/webauthn/#sctn-createCredential
 */
export async function create(
    createOptions: CreateAuthenticatorOptions,
    options: PublicKeyCredentialCreationOptions,
    signal?: AbortSignal,
): Promise<PublicKeyCredential | null> {
    const { rpId, ...normalizedOptions } = normalizeCreateOption(options)
    const timeout = normalizedOptions.timeout as number
    const abortController = new AbortController()
    const expiredSignal = abortController.signal

    setTimeout(() => abortController.abort(), timeout)

    const credTypesAndPubKeyAlgorithms = [] as { type: string; alg: number }[]
    // If this array contains multiple elements, they are sorted by descending order of preference.
    // We only support `ES256` algorithm
    if (Array.isArray(options.pubKeyCredParams) && options.pubKeyCredParams.length > 0) {
        for (const param of options.pubKeyCredParams) {
            if (param.type !== 'public-key') {
                // we only allow 'public-key'
                // continue
            } else {
                credTypesAndPubKeyAlgorithms.push({ type: param.type, alg: param.alg })
            }
        }
    } else {
        // default algorithm
        credTypesAndPubKeyAlgorithms.push({ type: 'public-key', alg: Alg.ES256 })
    }

    const collectedClientData: CollectedClientData = {
        type: 'webauthn.create',
        challenge: bytesToBase64(new Uint8Array(normalizedOptions.challenge)),
        origin: rpId,
        crossOrigin: normalizedOptions.crossOrigin,
        tokenBinding: undefined,
    }

    if (signal?.aborted) {
        throw new DOMException('AbortError')
    }

    if (expiredSignal.aborted) {
        return null
    } else {
        const { excludeCredentials = [], authenticatorSelection = {} } = options
        const {
            authenticatorAttachment = 'cross-platform',
            requireResidentKey = true,
            residentKey = 'required',
            userVerification = 'required',
        } = authenticatorSelection

        // In document, 'platform' means authenticator is bound to the client and is generally not removable.
        //  and 'cross-platform' means a device which may be used across different platform (NFC, USB)
        // However, in our library, 'cross-platform' means that the private key could sync with other platform using network, and vice versa.
        if (authenticatorAttachment === 'cross-platform') {
            let needResidentKey: boolean = requireResidentKey
            switch (residentKey) {
                case 'discouraged':
                    throw new TypeError('Not support')
                case 'required':
                case 'preferred':
                default:
                    needResidentKey = true
                    break
            }
            const needUserVerification = checkUserVerification(userVerification)

            if (!needResidentKey) {
                throw new TypeError('must require resident key')
            }

            if (!needUserVerification) {
                // must allow user verification
                throw new TypeError('must user verification')
            }
            // tip: skip enterprise attestation

            let keys: CryptoKeyPair
            let credentialID: ArrayBuffer
            // see https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions/excludeCredentials
            //  this option used for the server to create new credentials for an existing user.
            if (Array.isArray(excludeCredentials) && excludeCredentials.length > 0) {
                ;[keys, credentialID] = await createOptions.createKeyPairByKeyWrap(
                    rpId,
                    filterCredentials(excludeCredentials),
                )
                if (!keys) {
                    throw new Error('')
                }
            }
            ;[keys, credentialID] = await createOptions.getResidentKeyPair(rpId)
            const signCount = await createOptions.getSignCount(keys.privateKey, rpId, credentialID)
            const response = await generateCreationResponse(
                credentialID,
                keys,
                signCount,
                rpId,
                collectedClientData,
                credTypesAndPubKeyAlgorithms.map((alg) => alg.alg),
                expiredSignal,
            )
            createOptions.incrementSignCount(keys.privateKey, rpId, credentialID).catch(console.error)
            return response
        } else {
            // ignore 'platform'
            throw new Error('Not Support')
        }
    }
}
