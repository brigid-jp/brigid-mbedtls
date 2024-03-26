local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local ctr_drbg = mbedtls.ctr_drbg():seed(mbedtls.entropy())

local pk = mbedtls.pk():parse_key(test.secp256r1_1.key_pem, ctr_drbg)
assert(pk:write_key_pem() == test.secp256r1_1.key_pem)
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)

local pk = mbedtls.pk():parse_public_key(test.secp256r1_1.pub_pem, ctr_drbg)
assert(pk:write_key_pem() ~= test.secp256r1_1.key_pem)
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)
