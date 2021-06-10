import { isRegistrableDomain } from '../backend/util'

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
