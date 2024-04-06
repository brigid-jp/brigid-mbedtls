local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local ctr_drbg = mbedtls.ctr_drbg():seed(mbedtls.entropy())

local pk = mbedtls.pk():parse_key(test.secp256r1_1.key_pem, ctr_drbg)
assert(pk:write_key_pem() == test.secp256r1_1.key_pem)
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)

local pk = mbedtls.pk():parse_public_key(test.secp256r1_1.pub_pem, ctr_drbg)
-- 秘密鍵が存在しない場合の挙動が変わった。
-- v3.5.2: 空の秘密鍵
-- v3.6.0: エラー
if mbedtls.version.get_number() < 0x03060000 then
  assert(pk:write_key_pem() ~= test.secp256r1_1.key_pem)
else
  test.assume_error(function () pk:write_key_pem() end)
end
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)
