import { hasNativeCryptoSupport, aes } from '../src/crypto.js'

const assert = chai.assert
const pbkdf2FewIterationForTests = 1
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
        .generateKey(passwordForTest, pbkdf2FewIterationForTests)
        .then((results) => {
          console.log('aesGenerateKey results: ', results)
          assert.isDefined(results)
          assert.deepEqual(
            ['key', 'wrappedKey', 'derivation'],
            Object.keys(results)
          )
        })
    })
    it('should return a AES-GCM-256 key', () => {
      return aes
        .generateKey(passwordForTest, pbkdf2FewIterationForTests)
        .then(({ key }) => {
          assert.include({ name: 'AES-GCM', length: 256 }, key.algorithm)
        })
    })
    it('should return derivation parameters', () => {
      return aes
        .generateKey(passwordForTest, pbkdf2FewIterationForTests)
        .then(({ derivation }) => {
          assert.deepEqual(
            ['name', 'iterations', 'salt'],
            Object.keys(derivation)
          )
          assert.equal('PBKDF2', derivation.name)
          assert.equal(pbkdf2FewIterationForTests, derivation.iterations)
          assert.equal(16, derivation.salt.length)
        })
    })
    it('should return a AES-GCM-256 wrapped key', () => {
      return aes
        .generateKey(passwordForTest, pbkdf2FewIterationForTests)
        .then(({ wrappedKey }) => {
          assert.deepEqual(['key', 'iv'], Object.keys(wrappedKey))
          assert.equal(44, wrappedKey.key.byteLength)
          assert.equal(12, wrappedKey.iv.length)
        })
    })
  })
})
