local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local function test_aes128gcm(mode, cek, nonce, input)
  local gcm = mbedtls.gcm()
    :setkey(mbedtls.cipher.ID_AES, cek)
    :starts(mode, nonce)
  local output1 = gcm:update(input)
  local output2, tag = gcm:finish(16)
  return output1..output2, tag
end

local plaintext, tag = test_aes128gcm(
    mbedtls.gcm.DECRYPT,
    test.rfc8188.CEK,
    test.rfc8188.NONCE,
    test.rfc8188.ciphertext)
assert(plaintext == test.rfc8188.plaintext)
assert(tag == test.rfc8188.tag)

local ciphertext , tag = test_aes128gcm(
    mbedtls.gcm.ENCRYPT,
    test.rfc8188.CEK,
    test.rfc8188.NONCE,
    test.rfc8188.plaintext)
assert(ciphertext == test.rfc8188.ciphertext)
assert(tag == test.rfc8188.tag)
