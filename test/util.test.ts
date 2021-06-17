/* eslint-env jest */
/* eslint no-bitwise:off */
import {
  ccdToString,
  concatenate,
  isRegistrableDomain,
  serializeCollectedClientData
} from '../backend/util'

function parseAuthData (buffer: ArrayBuffer) {
  const textDecoder = new TextDecoder()
  const rpIdHash = buffer.slice(0, 32)
  buffer = buffer.slice(32)
  textDecoder.decode(buffer)

  const flagsBuf = buffer.slice(0, 1)
  buffer = buffer.slice(1)
  const flagsInt = new Uint8Array(flagsBuf)[0]
  const flags = {
    up: !!(flagsInt & 0x01),
    uv: !!(flagsInt & 0x04),
    at: !!(flagsInt & 0x40),
    ed: !!(flagsInt & 0x80),
    flagsInt
  }
  const counterBuf = buffer.slice(0, 4)
  buffer = buffer.slice(4)

  let bufferView = new DataView(counterBuf)
  const counter = bufferView.getUint32(0)
  let aaguid
  let credID
  let COSEPublicKey
  if (flags.at) {
    aaguid = buffer.slice(0, 16)
    buffer = buffer.slice(16)
    const credIDLenBuf = buffer.slice(0, 2)
    buffer = buffer.slice(2)
    bufferView = new DataView(credIDLenBuf)
    const credIDLen = bufferView.getUint16(0)
    credID = buffer.slice(0, credIDLen)
    buffer = buffer.slice(credIDLen)
    COSEPublicKey = buffer
  }
  return {
    rpIdHash,
    flagsBuf,
    flags,
    counter,
    counterBuf,
    aaguid,
    credID,
    COSEPublicKey
  }
}

test('is registrable domain', () => {
  expect(isRegistrableDomain('', '')).toBe(false)
  expect(isRegistrableDomain('google.com', 'google.cn')).toBe(false)
  expect(isRegistrableDomain('http://google.com', 'https://google.com'))
    .toBe(false)
  expect(isRegistrableDomain('https://foo.google.com', 'google.cn')).toBe(false)
  expect(isRegistrableDomain('https://google.com', 'google.com')).toBe(true)
  expect(isRegistrableDomain('https://google.com', 'https://google.cn'))
    .toBe(false)
  expect(isRegistrableDomain('https://test.google.com', 'https://google.com'))
    .toBe(true)
  expect(isRegistrableDomain('www.google.com', 'google.com')).toBe(true)
})

test('serialize collected clientData', () => {
  const challenge = new Uint8Array(16)
  challenge.set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], 0)
  expect(serializeCollectedClientData({
    type: 'webauthn.create',
    origin: 'https://google.com',
    crossOrigin: false,
    challenge: challenge,
    tokenBinding: undefined
  })).toMatchSnapshot('serialized collected client data')
})

test('ccd to string', () => {
  expect(ccdToString('http://google.com/foo?=123'))
    .toBe('"http://google.com/foo?=123"')
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
  const res = concatenate(a.buffer, b.buffer, c.buffer)
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
