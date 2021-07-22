/* eslint-env jest */
import { ccdToString, concatenate, isRegistrableDomain, serializeCollectedClientData } from '../src/backend/util'

test('is registrable domain', () => {
    expect(isRegistrableDomain('', '')).toBe(false)
    expect(isRegistrableDomain('google.com', 'google.cn')).toBe(false)
    expect(isRegistrableDomain('http://google.com', 'https://google.com')).toBe(false)
    expect(isRegistrableDomain('https://foo.google.com', 'google.cn')).toBe(false)
    expect(isRegistrableDomain('https://google.com', 'google.com')).toBe(true)
    expect(isRegistrableDomain('https://google.com', 'https://google.cn')).toBe(false)
    expect(isRegistrableDomain('https://test.google.com', 'https://google.com')).toBe(true)
    expect(isRegistrableDomain('www.google.com', 'google.com')).toBe(true)
})

test('serialize collected clientData', () => {
    const challenge = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).toString('base64')
    expect(
        serializeCollectedClientData({
            type: 'webauthn.create',
            origin: 'https://google.com',
            crossOrigin: false,
            challenge: challenge,
            tokenBinding: undefined,
        }),
    ).toMatchSnapshot('serialized collected client data')
})

test('contact buffer', () => {
    const view = new DataView(new Uint16Array(1).buffer)
    view.setUint16(0, 4096, false)
    expect(concatenate(view.buffer)).toEqual(view.buffer)
})

test('ccd to string', () => {
    expect(ccdToString('http://google.com/foo?=123')).toBe('"http://google.com/foo?=123"')
    expect(ccdToString('Bob: "你好！"')).toBe('"Bob: \\"你好！\\""')
    expect(ccdToString('hello, world!')).toBe('"hello, world!"')
    expect(ccdToString('𩸽')).toBe('"\\ud867de3d"')
})

test('buffer contact check', () => {
    const a = new Uint8Array(4)
    const b = new Uint32Array(1)
    const c = new Uint16Array(2)
    a.set([0xf7, 0x7e, 0x7e, 0x7f], 0)
    b.set([0x3ff77ff3], 0)
    c.set([0x3ff3, 0x1122], 0)
    const res = concatenate(a, b, c)
    expect(res.byteLength).toBe(12)
    const dataView = new DataView(res)
    expect(dataView.getUint8(0)).toBe(0xf7)
    expect(dataView.getUint8(1)).toBe(0x7e)
    expect(dataView.getUint8(2)).toBe(0x7e)
    expect(dataView.getUint8(3)).toBe(0x7f)
    // 0x3f f7 7f f3
    expect(dataView.getUint8(4)).toBe(0xf3)
    expect(dataView.getUint8(5)).toBe(0x7f)
    expect(dataView.getUint8(6)).toBe(0xf7)
    expect(dataView.getUint8(7)).toBe(0x3f)
    // 0x3f f3
    expect(dataView.getUint8(8)).toBe(0xf3)
    expect(dataView.getUint8(9)).toBe(0x3f)
    expect(dataView.getUint8(10)).toBe(0x22)
    expect(dataView.getUint8(11)).toBe(0x11)
})
