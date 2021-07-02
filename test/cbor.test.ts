import { parseJsonWebKey, toByteArray, UTF8String } from '../backend/cbor'

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
    expect(toByteArray(0xff)).toStrictEqual(Buffer.from([0xff]))
    expect(toByteArray(0x3f7f)).toStrictEqual(Buffer.from([0x3f, 0x7f]))
    expect(toByteArray(0x3f7ffc)).toStrictEqual(Buffer.from([0x00, 0x3f, 0x7f, 0xfc]))
    expect(toByteArray(2 ** 32 - 1)).toStrictEqual(Buffer.from([0xff, 0xff, 0xff, 0xff]))
    expect(toByteArray(2 ** 32)).toStrictEqual(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]))
    expect(toByteArray(2 ** 32 + 1)).toStrictEqual(Buffer.from([0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01]))
})
