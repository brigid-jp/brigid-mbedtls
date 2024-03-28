local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
local pk = mbedtls.pk():parse_key(test.secp256r1_1.key_pem)
local ec = pk:get_ec()
local key = ec:get_key()
local pub = ec:get_public_key()
local r = mbedtls.mpi():read_binary(test.ecdsa.r)
local s = mbedtls.mpi():read_binary(test.ecdsa.s)

mbedtls.ecdsa.verify(group, test.sha256.hash, pub, r, s)
mbedtls.ecdsa.verify(group, test.sha256.hash, pub, test.ecdsa.r..test.ecdsa.s)

local r, s = mbedtls.ecdsa.sign_det_ext(group, key, test.sha256.hash, mbedtls.md.SHA256)
mbedtls.ecdsa.verify(group, test.sha256.hash, pub, r, s)

local signature = mbedtls.ecdsa.sign(group, key, test.sha256.hash, mbedtls.md.SHA256)
mbedtls.ecdsa.verify(group, test.sha256.hash, pub, signature)

test.assume_error(mbedtls.ecdsa.verify, group, test.sha256.hash, pub, s, r)
test.assume_error(mbedtls.ecdsa.verify, group, test.sha256.hash, pub, test.ecdsa.s..test.ecdsa.r)
test.assume_error(mbedtls.ecdsa.verify, group, test.sha256.hash, pub, test.ecdsa.r..test.ecdsa.s.."    ")
