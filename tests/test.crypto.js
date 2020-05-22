import {
  hasNativeCryptoSupport,
  generateRandomString,
  convertByteToReadableChar,
  derivation,
  aes,
} from '../src/crypto.js'

const assert = chai.assert

const passwordForTest = 'passwordForTest'

const derivationParamsForTest = {
  type: 2,
  time: 1,
  mem: 10,
  parallelism: 1,
  salt: "At*$+r94>8nJNfGt'; UM*8BW&]K3tEl",
}

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
  describe('convertByteToReadableChar', () => {
    it(`should convert 0 to ' '`, () => {
      assert.equal(' ', convertByteToReadableChar(0))
    })
    it(`should convert 1 to !`, () => {
      assert.equal('!', convertByteToReadableChar(1))
    })
    it(`should convert 33 to A`, () => {
      assert.equal('A', convertByteToReadableChar(33))
    })
    it(`should convert 65 to a`, () => {
      assert.equal('a', convertByteToReadableChar(65))
    })
    it(`should convert 94 to ~`, () => {
      assert.equal('~', convertByteToReadableChar(94))
    })
    it(`should convert 95 to ' ' (loop again)`, () => {
      assert.equal(' ', convertByteToReadableChar(95))
    })
    it(`should convert 128 to A`, () => {
      assert.equal('A', convertByteToReadableChar(128))
    })
    it(`should convert 255 to a`, () => {
      assert.equal('a', convertByteToReadableChar(255))
    })
    it(`any value should be above ascii char 32`, () => {
      assert.equal(32, ' '.charCodeAt(0), 'ascii value for space is 32')
      for (let i = 0; i < 255; i++) {
        const c = convertByteToReadableChar(i)
        assert.ok(
          c.charCodeAt(0) >= 32,
          'character should not be below 32 (space)'
        )
      }
    })
    it(`any value should be below ascii char 126 (tilde)`, () => {
      assert.equal(126, '~'.charCodeAt(0), 'ascii value for tile is 126')
      for (let i = 0; i < 255; i++) {
        const c = convertByteToReadableChar(i)
        assert.ok(
          c.charCodeAt(0) <= 126,
          'character should not be above 126 (tile)'
        )
      }
    })
  })
  describe('generateRandomString', () => {
    it('should return 2 differents strings', () => {
      const s1 = generateRandomString()
      const s2 = generateRandomString()
      console.log('generateRandomString', s1, ' !== ', s2)
      assert.notEqual(s1, s2)
    })
    it('should return a string of 32 characters by default', () => {
      assert.equal(32, generateRandomString().length)
    })
    it('should return a string of asked size', () => {
      const s = 10
      assert.equal(s, generateRandomString(s).length)
    })
  })
  describe('derivation', () => {
    describe('getDerivationParams', () => {
      it('should return default parameters', () => {
        const params = derivation.getDerivationParams()
        console.log('getDerivationParams:', params)
        assert.deepEqual(
          ['type', 'time', 'mem', 'parallelism', 'salt'],
          Object.keys(params)
        )
        assert.equal(2, params.type)
        assert.equal(100, params.time)
        assert.equal(1024, params.mem)
        assert.equal(1, params.parallelism)
        assert.equal(32, params.salt.length, 'salt should be 32 char long')
      })
      it('should keep parameters passed', () => {
        const type = 1
        const time = 2
        const mem = 3
        const parallelism = 4
        const salt = 'abcdef'
        const params = derivation.getDerivationParams({
          type,
          time,
          mem,
          parallelism,
          salt,
        })
        assert.deepEqual(
          ['type', 'time', 'mem', 'parallelism', 'salt'],
          Object.keys(params)
        )
        assert.equal(type, params.type)
        assert.equal(time, params.time)
        assert.equal(mem, params.mem)
        assert.equal(parallelism, params.parallelism)
        assert.equal(salt, params.salt)
      })
    })
    describe('derivateKey', () => {
      it('should derivate a key from specific value', () => {
        return derivation
          .derivateKey(passwordForTest, derivationParamsForTest)
          .then((results) => {
            console.log('derivateKey:', results)
            assert.deepEqual(
              ['hash', 'hashHex', 'encoded', 'derivationParams'],
              Object.keys(results)
            )
            assert.equal(
              '65288a696e470eedb1b34216df5d7f8b3dd7542f25b20fcfd0aace5a718b7246',
              results.hashHex
            )
            assert.equal(
              '$argon2id$v=19$m=10,t=1,p=1$QXQqJCtyOTQ+OG5KTmZHdCc7IFVNKjhCVyZdSzN0RWw$ZSiKaW5HDu2xs0IW311/iz3XVC8lsg/P0KrOWnGLckY',
              results.encoded
            )
          })
      })
    })
  })

  //  describe('aes.generateKey', (results) => {
  //    it('should return a key, wrapping key and pbkdf2 data', () => {
  //      return aes
  //        .generateKey(passwordForTest, derivationParams)
  //        .then((results) => {
  //          console.log('aes.generateKey results:', results)
  //          assert.isDefined(results)
  //          assert.deepEqual(
  //            ['key', 'wrappedKey', 'derivation'],
  //            Object.keys(results)
  //          )
  //        })
  //    })
  //    it('should return a AES-GCM-256 key', () => {
  //      return aes
  //        .generateKey(passwordForTest, derivationParams)
  //        .then(({ key }) => {
  //          assert.include({ name: 'AES-GCM', length: 256 }, key.algorithm)
  //        })
  //    })
  //    it('should return derivation parameters', () => {
  //      return aes
  //        .generateKey(passwordForTest, derivationParams)
  //        .then(({ derivation }) => {
  //          assert.deepEqual(
  //            ['name', 'iterations', 'salt'],
  //            Object.keys(derivation)
  //          )
  //          assert.equal('PBKDF2', derivation.name)
  //          assert.equal(derivationParams.iterations, derivation.iterations)
  //          assert.equal(16, derivation.salt.length)
  //        })
  //    })
  //    it('should return a AES-GCM-256 wrapped key', () => {
  //      return aes
  //        .generateKey(passwordForTest, derivationParams)
  //        .then(({ wrappedKey }) => {
  //          assert.deepEqual(
  //            ['key', 'name', 'iv', 'tagLength'],
  //            Object.keys(wrappedKey)
  //          )
  //          assert.equal(44, wrappedKey.key.byteLength)
  //          assert.equal(12, wrappedKey.iv.length)
  //        })
  //    })
  //  })
  //})
  //describe('aes.encrypt', (results) => {
  //  const clearTextMessage = 'Hello World'
  //  it('should encrypt', () => {
  //    return aes
  //      .generateKey(passwordForTest, derivationParams)
  //      .then(({ key }) => aes.encrypt(key, clearTextMessage))
  //      .then((results) => {
  //        console.log('aes.encrypt results:', results)
  //        assert.deepEqual(
  //          ['encryptedData', 'name', 'iv', 'tagLength'],
  //          Object.keys(results)
  //        )
  //      })
  //  })
})
