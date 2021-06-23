/* eslint-env jest */
import { generateCreationResponse, PublicKeyAlgorithm } from '../backend/authenticator'
import { Buffer } from 'buffer'
import { decode } from 'cbor-redux'
import { verify } from '../api/util'

test('generate response', async () => {
    const credentialID = new Uint8Array(16).map((_, index) => index % 8)
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const challenge = new Uint8Array(16).fill(3)
    const signCount = 0
    const rpID = 'https://maskbook.io'
    const response = await generateCreationResponse(
        credentialID,
        keys,
        signCount,
        rpID,
        {
            type: 'webauthn.create',
            challenge,
            origin: rpID,
            crossOrigin: false,
            tokenBinding: undefined,
        },
        [-7],
    )
    expect(Buffer.from(response.rawId).toString('base64')).toBe(response.id)
    const { clientDataJSON, attestationObject } = response.response as AuthenticatorAttestationResponse
    const dataJson = JSON.parse(Buffer.from(clientDataJSON).toString())
    expect(typeof dataJson).toBe('object')
    expect(Buffer.from(dataJson.challenge.data as ArrayBuffer).every((v) => v === 3)).toBe(true)
    const attestation = decode(attestationObject)
    expect(attestation.fmt).toBe('packed')
    expect(attestation.attStmt.alg).toBe(PublicKeyAlgorithm.ES256)
    expect(await verify(keys.publicKey, response)).toBe(true)
})
