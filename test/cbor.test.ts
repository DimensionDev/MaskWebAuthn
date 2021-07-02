import { Number, parseJsonWebKey, UTF8String } from '../backend/cbor'

test('parseJsonWebKey', () => {
    expect(parseJsonWebKey({})).toStrictEqual(Buffer.from([0xbf, 0xff]))
    expect(
        parseJsonWebKey({
            x: '',
        }),
    ).toStrictEqual(Buffer.from([0xbf, 0x21, 0x40, 0xff]))
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
