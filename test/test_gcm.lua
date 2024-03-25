local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"

-- https://datatracker.ietf.org/doc/html/rfc8188
local cek_bin = string.char(
  0xff, 0x09, 0xe2, 0xca, 0xd0, 0x7e, 0xa1, 0xfb,
  0x1c, 0x64, 0x38, 0x78, 0xb5, 0xb4, 0xa3, 0x1f
)

local nonce_bin = string.char(
  0x05, 0xcb, 0x3c, 0x82, 0x42, 0x11, 0x28, 0xb2,
  0x3c, 0x19, 0xe2, 0x3c
)

local decrypted_bin = "I am the walrus\2"

local encrypted_bin = string.char(
  0xf8, 0xd0, 0x15, 0xb9, 0xbd, 0xaa, 0x16, 0x00,
  0x44, 0xb9, 0x02, 0x91, 0x6a, 0x9a, 0x19, 0xbb
)

local tag_bin = string.char(
  0xe2, 0x31, 0x90, 0x8b, 0xda, 0xdc, 0xc1, 0x01,
  0xd4, 0xf0, 0xfe, 0x97, 0x2f, 0x13, 0x86, 0x38
)

local gcm = mbedtls.gcm():setkey(mbedtls.cipher.ID_AES, cek_bin)
local buffer = {}
local tag
gcm:starts(mbedtls.gcm.DECRYPT, nonce_bin)
buffer[1] = gcm:update(encrypted_bin)
buffer[2], tag = gcm:finish(16)
local result = table.concat(buffer)
assert(result == decrypted_bin)
assert(tag == tag_bin)

local gcm = mbedtls.gcm():setkey(mbedtls.cipher.ID_AES, cek_bin)
local buffer = {}
local tag
gcm:starts(mbedtls.gcm.ENCRYPT, nonce_bin)
buffer[1] = gcm:update(decrypted_bin)
buffer[2], tag = gcm:finish(16)
local result = table.concat(buffer)
assert(result == encrypted_bin)
assert(tag == tag_bin)
