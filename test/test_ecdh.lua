local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local pk1 = mbedtls.pk():parse_key(test.secp256r1_1.key_pem)
local pk2 = mbedtls.pk():parse_public_key(test.secp256r1_2.pub_pem)
local secret = mbedtls.ecdh()
  :setup(mbedtls.ecp.DP_SECP256R1)
  :get_params(pk1:get_ec(), mbedtls.ecdh.OURS)
  :get_params(pk2:get_ec(), mbedtls.ecdh.THEIRS)
  :calc_secret()
assert(secret == test.ecdh.secret)
