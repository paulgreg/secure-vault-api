import {
  hasNativeCryptoSupport,
  generateRandomString,
  convertByteToReadableChar,
  arrayBufferToUint8Array,
  deserializeUint8Array,
  derivation,
  createIdentity,
  loadIdentity,
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
  describe('ArrayBuffer conversion', () => {
    it('serializeArrayBuffer', () => {
      const inputArray = new Uint8Array([1, 2, 3])
      const buffer = inputArray.buffer
      const outputArray = arrayBufferToUint8Array(buffer)
      assert.equal(inputArray.length, outputArray.length)
      for (let i = 0; i < inputArray.length; i++) {
        assert.equal(inputArray[i], outputArray[i])
      }
    })
    it('Uint8array saved to json then deserialize', () => {
      const data = new Uint8Array([1, 2, 3])
      const dataInJson = JSON.stringify(data)
      const dataResoredFromJson = JSON.parse(dataInJson)
      const desieralizedData = deserializeUint8Array(dataResoredFromJson)
      assert.equal(
        data.length,
        desieralizedData.length,
        'array has different size after deserialization'
      )
      for (let i = 0; i < data.length; i++) {
        assert.equal(data[i], desieralizedData[i])
      }
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
            assert.isDefined(results)
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

  describe('createIdentify', () => {
    it('should should throw error if no password', () =>
      createIdentity().catch((e) => assert.equal('PASSWORD_EMPTY', e.message)))

    it('should should throw error if password < 8 chars', () =>
      createIdentity('1234567').catch((e) =>
        assert.equal('PASSWORD_TOO_SHORT', e.message)
      ))

    it('should return derivationParams, keyEncryptionKey, fileEncryptionKey, wrappedFileEncryptionKey and wrappedFileEncryptionKeyParams', () => {
      return createIdentity(passwordForTest, {
        derivationParams: derivationParamsForTest,
      }).then((results) => {
        console.log('createIdentity:', JSON.stringify(results))
        assert.isDefined(results)
        assert.deepEqual(
          [
            'derivationParams',
            'keyEncryptionKey',
            'fileEncryptionKey',
            'wrappedFileEncryptionKey',
            'wrappedFileEncryptionKeyParams',
          ],
          Object.keys(results)
        )
        assert.deepEqual(
          ['name', 'iv', 'tagLength'],
          Object.keys(results.wrappedFileEncryptionKeyParams)
        )
        assert.equal(
          'AES-GCM',
          results.wrappedFileEncryptionKeyParams.name,
          'bad AES key algorithm'
        )
        assert.equal(
          96,
          results.wrappedFileEncryptionKeyParams.tagLength,
          'bad tag length'
        )
        assert.equal(
          12,
          results.wrappedFileEncryptionKeyParams.iv.length,
          'bad IV size'
        )
      })
    })
  })
  describe('loadIdentity', () => {
    it('should should throw error if no password', () =>
      loadIdentity().catch((e) => assert.equal('PASSWORD_EMPTY', e.message)))

    it('should should throw error if password < 8 chars', () =>
      loadIdentity('1234567').catch((e) =>
        assert.equal('PASSWORD_TOO_SHORT', e.message)
      ))

    it('should load previous identity', () => {
      const derivationParams = {
        type: 2,
        time: 1,
        mem: 10,
        parallelism: 1,
        salt: "At*$+r94>8nJNfGt'; UM*8BW&]K3tEl",
      }

      const wrappedFileEncryptionKey = {
        '0': 109,
        '1': 67,
        '2': 175,
        '3': 2,
        '4': 160,
        '5': 153,
        '6': 251,
        '7': 21,
        '8': 249,
        '9': 158,
        '10': 63,
        '11': 5,
        '12': 95,
        '13': 211,
        '14': 190,
        '15': 170,
        '16': 136,
        '17': 247,
        '18': 95,
        '19': 84,
        '20': 163,
        '21': 189,
        '22': 155,
        '23': 203,
        '24': 104,
        '25': 112,
        '26': 80,
        '27': 212,
        '28': 82,
        '29': 102,
        '30': 184,
        '31': 216,
        '32': 15,
        '33': 79,
        '34': 14,
        '35': 58,
        '36': 24,
        '37': 38,
        '38': 157,
        '39': 7,
        '40': 66,
        '41': 60,
        '42': 177,
        '43': 146,
      }
      const wrappedFileEncryptionKeyParams = {
        name: 'AES-GCM',
        iv: {
          '0': 112,
          '1': 164,
          '2': 41,
          '3': 211,
          '4': 174,
          '5': 206,
          '6': 195,
          '7': 202,
          '8': 211,
          '9': 160,
          '10': 90,
          '11': 169,
        },
        tagLength: 96,
      }

      return loadIdentity(passwordForTest, {
        derivationParams,
        wrappedFileEncryptionKey,
        wrappedFileEncryptionKeyParams,
      }).then((results) => {
        console.log('loadIdentity', JSON.stringify(results))
        assert.isDefined(results)
        assert.deepEqual(
          [
            'fileEncryptionKey'
          ],
          Object.keys(results)
        )
      })
    })
  })
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
