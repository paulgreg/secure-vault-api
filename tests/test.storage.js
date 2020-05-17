import { hasLocalStorageSupport } from '../src/storage.js'

const assert = chai.assert

describe('storage', function () {
  describe('hasLocalStorageSupport ', function () {
    it('should return true', function () {
      assert.isTrue(hasLocalStorageSupport())
    })
  })
})
