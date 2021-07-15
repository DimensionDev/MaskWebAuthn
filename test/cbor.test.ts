import { encode, Number, parseJsonWebKey, UTF8String } from '../backend/cbor'
import { encode as reduxEncode, decode } from 'cbor-redux'
import { concatenate } from '../backend/util'
import { ecJwk } from './util'

const validCborPublicKey = new Uint8Array([
    -91, 1, 2, 3, 38, 32, 1, 33, 88, 32, -13, 21, 122, -20, 72, -61, 72, 112, 94, -105, -105, 29, -8, -87, 13, 85, 82,
    31, -63, -104, 111, -52, -18, 42, 82, -7, -68, -11, 4, -12, 7, -49, 34, 88, 32, 45, -107, 76, 61, -28, 37, -64, 30,
    -20, -99, -82, 108, -76, 35, 35, -62, 126, -77, -16, -116, -128, 91, -44, 27, -20, 65, 1, 12, -79, 52, 109, -88,
])

// valid key example from chrome
const key = decode(validCborPublicKey.buffer)

test('parseJsonWebKey', () => {
    expect(parseJsonWebKey({})).toStrictEqual(Buffer.from([0xa0]).buffer)
    expect(
        parseJsonWebKey({
            x: '',
        }),
    ).toStrictEqual(Buffer.from([0xa1, 0x21, 0x60]).buffer)
})

test('UTF8String', () => {
    // see https://datatracker.ietf.org/doc/html/rfc8949#appendix-A
    expect(UTF8String('')).toStrictEqual(Buffer.from([0x60]).buffer)
    expect(UTF8String('a')).toStrictEqual(Buffer.from([0x61, 0x61]).buffer)
    expect(UTF8String('IETF')).toStrictEqual(Buffer.from([0x64, 0x49, 0x45, 0x54, 0x46]).buffer)
    expect(UTF8String('"\\')).toStrictEqual(Buffer.from([0x62, 0x22, 0x5c]).buffer)
    expect(UTF8String('\u00fc')).toStrictEqual(Buffer.from([0x62, 0xc3, 0xbc]).buffer)
    expect(UTF8String('\u6c34')).toStrictEqual(Buffer.from([0x63, 0xe6, 0xb0, 0xb4]).buffer)
    expect(UTF8String('\ud800\udd51')).toStrictEqual(Buffer.from([0x64, 0xf0, 0x90, 0x85, 0x91]).buffer)
})

test('toByteArray', () => {
    expect(Number(0)).toStrictEqual(Buffer.from([0x00]).buffer)
    expect(Number(1)).toStrictEqual(Buffer.from([0x01]).buffer)
    expect(Number(10)).toStrictEqual(Buffer.from([0x0a]).buffer)
    expect(Number(23)).toStrictEqual(Buffer.from([0x17]).buffer)
    expect(Number(24)).toStrictEqual(Buffer.from([0x18, 0x18]).buffer)
    expect(Number(25)).toStrictEqual(Buffer.from([0x18, 0x19]).buffer)
    expect(Number(100)).toStrictEqual(Buffer.from([0x18, 0x64]).buffer)
    expect(Number(1000)).toStrictEqual(Buffer.from([0x19, 0x03, 0xe8]).buffer)
    expect(Number(1000000)).toStrictEqual(Buffer.from([0x1a, 0x00, 0x0f, 0x42, 0x40]).buffer)
    expect(Number(1000000000000)).toStrictEqual(
        Buffer.from([0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]).buffer,
    )
})

test('encode', () => {
    expect(encode('')).toStrictEqual(Buffer.from([0x60]).buffer)
    expect(encode('a')).toStrictEqual(Buffer.from([0x61, 0x61]).buffer)
    expect(encode('IETF')).toStrictEqual(Buffer.from([0x64, 0x49, 0x45, 0x54, 0x46]).buffer)
    expect(encode('"\\')).toStrictEqual(Buffer.from([0x62, 0x22, 0x5c]).buffer)
    expect(encode('\u00fc')).toStrictEqual(Buffer.from([0x62, 0xc3, 0xbc]).buffer)
    expect(encode('\u6c34')).toStrictEqual(Buffer.from([0x63, 0xe6, 0xb0, 0xb4]).buffer)
    expect(encode('\ud800\udd51')).toStrictEqual(Buffer.from([0x64, 0xf0, 0x90, 0x85, 0x91]).buffer)
    expect(encode(0)).toStrictEqual(Buffer.from([0x00]).buffer)
    expect(encode(1)).toStrictEqual(Buffer.from([0x01]).buffer)
    expect(encode(10)).toStrictEqual(Buffer.from([0x0a]).buffer)
    expect(encode(23)).toStrictEqual(Buffer.from([0x17]).buffer)
    expect(encode(24)).toStrictEqual(Buffer.from([0x18, 0x18]).buffer)
    expect(encode(25)).toStrictEqual(Buffer.from([0x18, 0x19]).buffer)
    expect(encode(100)).toStrictEqual(Buffer.from([0x18, 0x64]).buffer)
    expect(encode(1000)).toStrictEqual(Buffer.from([0x19, 0x03, 0xe8]).buffer)
    expect(encode(1000000)).toStrictEqual(Buffer.from([0x1a, 0x00, 0x0f, 0x42, 0x40]).buffer)
    expect(encode(1000000000000)).toStrictEqual(
        Buffer.from([0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]).buffer,
    )
})

describe('match rfc 8152', () => {
    test('simple example', () => {
        const response = parseJsonWebKey({
            x: '',
        })
        expect(response).toStrictEqual(
            new Uint8Array([
                0xa1, // size 1 of map
                0x21, // negative number -1
                0x60, // utf8 string with empty
            ]).buffer,
        )
    })
    test('real example', () => {
        function jwkToCOSEKey(jwkLike: { x: string; y: string }): ArrayBuffer {
            const array: Uint8Array[] = []
            array.push(new Uint8Array([0xa5])) // size 5 of map
            array.push(new Uint8Array([0x01])) // key: kty
            array.push(new Uint8Array([0x02])) // value: EC
            array.push(new Uint8Array([0x20])) // key: crv
            array.push(new Uint8Array([0x01])) // value: P-256
            array.push(new Uint8Array([0x03])) // key: alg
            array.push(new Uint8Array([0x26])) // value: -7
            array.push(new Uint8Array(reduxEncode(-2))) // key: x
            array.push(new Uint8Array(reduxEncode(jwkLike.x)))
            array.push(new Uint8Array(reduxEncode(-3))) // key: y
            array.push(new Uint8Array(reduxEncode(jwkLike.y)))
            return concatenate(...array)
        }

        const expected = jwkToCOSEKey({
            x: ecJwk.x,
            y: ecJwk.y,
        })

        const actual = parseJsonWebKey({
            kty: ecJwk.kty,
            crv: ecJwk.crv,
            alg: ecJwk.alg,
            x: ecJwk.x,
            y: ecJwk.y,
        })

        expect(actual).toStrictEqual(expected)
    })
})
