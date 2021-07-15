/* eslint-env jest */
import { generateCreationResponse } from '../backend/authenticator'
import { Buffer } from 'buffer'
import { decode } from 'cbor-redux'
import { verify } from '../api/util'
import { verifyPackedAttestation } from './util'
import { Alg } from '../types/interface'

let credentialID: ArrayBuffer
let keys: CryptoKeyPair
let challenge: ArrayBuffer
let signCount: number
let rpID: string

beforeAll(async () => {
    credentialID = new Uint8Array(16).map((_, index) => index % 8)
    keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    challenge = new Uint8Array(16).fill(3)
    signCount = 0
    rpID = 'https://maskbook.io'
})

test('generate response', async () => {
    const response = await generateCreationResponse(
        credentialID,
        keys,
        signCount,
        rpID,
        {
            type: 'webauthn.create',
            challenge: Buffer.from(challenge).toString('base64'),
            origin: rpID,
            crossOrigin: false,
            tokenBinding: undefined,
        },
        [-7],
    )
    expect(Buffer.from(response.rawId).toString('base64')).toBe(response.id)
    const { clientDataJSON, attestationObject } = response.response
    const dataJson = JSON.parse(Buffer.from(clientDataJSON).toString())
    expect(typeof dataJson).toBe('object')
    expect(Buffer.from(dataJson.challenge, 'base64').every((v) => v === 3)).toBe(true)
    const attestation = decode(attestationObject)
    expect(attestation.fmt).toBe('packed')
    expect(attestation.attStmt.alg).toBe(Alg.ES256)
    expect(await verify(keys.publicKey, response)).toBe(true)
})

test('verify response', async () => {
    const response = await generateCreationResponse(
        credentialID,
        keys,
        signCount,
        rpID,
        {
            type: 'webauthn.create',
            challenge: Buffer.from(challenge).toString('base64'),
            origin: rpID,
            crossOrigin: false,
            tokenBinding: undefined,
        },
        [-7],
    )

    await verifyPackedAttestation(keys, response)
})
