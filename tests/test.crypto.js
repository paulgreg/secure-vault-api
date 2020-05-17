import { hasNativeCryptoSupport, aes } from '../src/crypto.js'

const assert = chai.assert
const pbkdf2FewIterationForTests = 1
const derivationParams = { iterations: pbkdf2FewIterationForTests }
const passwordForTest = 'password'

describe('crypto', () => {
  describe('hasNativeCryptoSupport', () => {
    it('should return true', () => {
      assert.isTrue(hasNativeCryptoSupport())
    })
  })
  describe('crypto.getRandomValues', () => {
    it('should return 2 differents 32 bits numbers', () => {
      assert.notEqual(
        window.crypto.getRandomValues(new Uint32Array(1)),
        window.crypto.getRandomValues(new Uint32Array(1))
      )
    })
  })
  describe('aes.generateKey', (results) => {
    it('should return a key, wrapping key and pbkdf2 data', () => {
      return aes
        .generateKey(passwordForTest, derivationParams)
        .then((results) => {
          console.log('aes.generateKey results:', results)
          assert.isDefined(results)
          assert.deepEqual(
            ['key', 'wrappedKey', 'derivation'],
            Object.keys(results)
          )
        })
    })
    it('should return a AES-GCM-256 key', () => {
      return aes
        .generateKey(passwordForTest, derivationParams)
        .then(({ key }) => {
          assert.include({ name: 'AES-GCM', length: 256 }, key.algorithm)
        })
    })
    it('should return derivation parameters', () => {
      return aes
        .generateKey(passwordForTest, derivationParams)
        .then(({ derivation }) => {
          assert.deepEqual(
            ['name', 'iterations', 'salt'],
            Object.keys(derivation)
          )
          assert.equal('PBKDF2', derivation.name)
          assert.equal(derivationParams.iterations, derivation.iterations)
          assert.equal(16, derivation.salt.length)
        })
    })
    it('should return a AES-GCM-256 wrapped key', () => {
      return aes
        .generateKey(passwordForTest, derivationParams)
        .then(({ wrappedKey }) => {
          assert.deepEqual(
            ['key', 'name', 'iv', 'tagLength'],
            Object.keys(wrappedKey)
          )
          assert.equal(44, wrappedKey.key.byteLength)
          assert.equal(12, wrappedKey.iv.length)
        })
    })
  })
})
describe('aes.encrypt', (results) => {
  const clearTextMessage = 'Hello World'
  it('should encrypt', () => {
    return aes
      .generateKey(passwordForTest, derivationParams)
      .then(({ key }) => aes.encrypt(key, clearTextMessage))
      .then((results) => {
        console.log('aes.encrypt results:', results)
        assert.deepEqual(
          ['encryptedData', 'name', 'iv', 'tagLength'],
          Object.keys(results)
        )
      })
  })
})
