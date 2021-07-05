import { encode, Number, parseJsonWebKey, UTF8String } from '../backend/cbor'

const validCborPublicKey = Buffer.from([
    -91, 1, 2, 3, 38, 32, 1, 33, 88, 32, -13, 21, 122, -20, 72, -61, 72, 112, 94, -105, -105, 29, -8, -87, 13, 85, 82,
    31, -63, -104, 111, -52, -18, 42, 82, -7, -68, -11, 4, -12, 7, -49, 34, 88, 32, 45, -107, 76, 61, -28, 37, -64, 30,
    -20, -99, -82, 108, -76, 35, 35, -62, 126, -77, -16, -116, -128, 91, -44, 27, -20, 65, 1, 12, -79, 52, 109, -88,
])

test('parseJsonWebKey', () => {
    expect(parseJsonWebKey({})).toStrictEqual(Buffer.from([0xa0]))
    expect(
        parseJsonWebKey({
            x: '',
        }),
    ).toStrictEqual(Buffer.from([0xa1, 0x21, 0x60]))
})

test('UTF8String', () => {
    // see https://datatracker.ietf.org/doc/html/rfc8949#appendix-A
    expect(UTF8String('')).toStrictEqual(Buffer.from([0x60]))
    expect(UTF8String('a')).toStrictEqual(Buffer.from([0x61, 0x61]))
    expect(UTF8String('IETF')).toStrictEqual(Buffer.from([0x64, 0x49, 0x45, 0x54, 0x46]))
    expect(UTF8String('"\\')).toStrictEqual(Buffer.from([0x62, 0x22, 0x5c]))
    expect(UTF8String('\u00fc')).toStrictEqual(Buffer.from([0x62, 0xc3, 0xbc]))
    expect(UTF8String('\u6c34')).toStrictEqual(Buffer.from([0x63, 0xe6, 0xb0, 0xb4]))
    expect(UTF8String('\ud800\udd51')).toStrictEqual(Buffer.from([0x64, 0xf0, 0x90, 0x85, 0x91]))
})

test('toByteArray', () => {
    expect(Number(0)).toStrictEqual(Buffer.from([0x00]))
    expect(Number(1)).toStrictEqual(Buffer.from([0x01]))
    expect(Number(10)).toStrictEqual(Buffer.from([0x0a]))
    expect(Number(23)).toStrictEqual(Buffer.from([0x17]))
    expect(Number(24)).toStrictEqual(Buffer.from([0x18, 0x18]))
    expect(Number(25)).toStrictEqual(Buffer.from([0x18, 0x19]))
    expect(Number(100)).toStrictEqual(Buffer.from([0x18, 0x64]))
    expect(Number(1000)).toStrictEqual(Buffer.from([0x19, 0x03, 0xe8]))
    expect(Number(1000000)).toStrictEqual(Buffer.from([0x1a, 0x00, 0x0f, 0x42, 0x40]))
    expect(Number(1000000000000)).toStrictEqual(Buffer.from([0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]))
})

test('encode', () => {
    expect(encode('')).toStrictEqual(Buffer.from([0x60]))
    expect(encode('a')).toStrictEqual(Buffer.from([0x61, 0x61]))
    expect(encode('IETF')).toStrictEqual(Buffer.from([0x64, 0x49, 0x45, 0x54, 0x46]))
    expect(encode('"\\')).toStrictEqual(Buffer.from([0x62, 0x22, 0x5c]))
    expect(encode('\u00fc')).toStrictEqual(Buffer.from([0x62, 0xc3, 0xbc]))
    expect(encode('\u6c34')).toStrictEqual(Buffer.from([0x63, 0xe6, 0xb0, 0xb4]))
    expect(encode('\ud800\udd51')).toStrictEqual(Buffer.from([0x64, 0xf0, 0x90, 0x85, 0x91]))
    expect(encode(0)).toStrictEqual(Buffer.from([0x00]))
    expect(encode(1)).toStrictEqual(Buffer.from([0x01]))
    expect(encode(10)).toStrictEqual(Buffer.from([0x0a]))
    expect(encode(23)).toStrictEqual(Buffer.from([0x17]))
    expect(encode(24)).toStrictEqual(Buffer.from([0x18, 0x18]))
    expect(encode(25)).toStrictEqual(Buffer.from([0x18, 0x19]))
    expect(encode(100)).toStrictEqual(Buffer.from([0x18, 0x64]))
    expect(encode(1000)).toStrictEqual(Buffer.from([0x19, 0x03, 0xe8]))
    expect(encode(1000000)).toStrictEqual(Buffer.from([0x1a, 0x00, 0x0f, 0x42, 0x40]))
    expect(encode(1000000000000)).toStrictEqual(Buffer.from([0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00]))
})
