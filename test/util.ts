export function parseAuthData (buffer: ArrayBuffer) {
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
