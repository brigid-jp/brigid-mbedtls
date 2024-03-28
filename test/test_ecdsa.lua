local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
local pk = mbedtls.pk():parse_key(test.secp256r1_1.key_pem)
local r = mbedtls.mpi():read_binary(test.ecdsa.r)
local s = mbedtls.mpi():read_binary(test.ecdsa.s)
mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), r, s)

local r, s = mbedtls.ecdsa.sign_det_ext(group, pk:get_ec():get_key(), test.sha256.hash, mbedtls.md.SHA256, ctr_drbg)
mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), r, s)
mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), test.ecdsa.r..test.ecdsa.s)

test.assume_error(function ()
  mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), s, r)
end)

test.assume_error(function ()
  mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), test.ecdsa.s..test.ecdsa.r)
end)

test.assume_error(function ()
  mbedtls.ecdsa.verify(group, test.sha256.hash, pk:get_ec():get_public_key(), test.ecdsa.r..test.ecdsa.s.."    ")
end)
