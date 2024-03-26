local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local ctr_drbg = mbedtls.ctr_drbg():seed(mbedtls.entropy())

local function debug_print_curve_info(info)
  if test.debug then
    print("grp_id: "..info.grp_id)
    print("tls_id: "..info.tls_id)
    print("bit_size: "..info.bit_size)
    print("name: "..info.name)
  end
end

local info = mbedtls.ecp.curve_info_from_grp_id(mbedtls.ecp.DP_SECP256R1)
debug_print_curve_info(info)

assert(info.grp_id == mbedtls.ecp.DP_SECP256R1)
assert(info.tls_id == 23)
assert(info.bit_size == 256)
assert(info.name == "secp256r1")

local info = mbedtls.ecp.curve_info_from_tls_id(25)
debug_print_curve_info(info)
assert(info.grp_id == mbedtls.ecp.DP_SECP521R1)
assert(info.tls_id == 25)
assert(info.bit_size == 521)
assert(info.name == "secp521r1")

local info = mbedtls.ecp.curve_info_from_name "x25519"
debug_print_curve_info(info)
assert(info.grp_id == mbedtls.ecp.DP_CURVE25519)
assert(info.tls_id == 29)
assert(info.bit_size == 256)
assert(info.name == "x25519")

local group = mbedtls.ecp.group():load(mbedtls.ecp.DP_SECP256R1)
assert(group:get_id() == mbedtls.ecp.DP_SECP256R1)

local keypair = mbedtls.ecp.keypair():gen_key(mbedtls.ecp.DP_SECP256R1, ctr_drbg)
local pk = mbedtls.pk():setup(mbedtls.pk.ECKEY):set_ec(keypair)
local key_pem = pk:write_key_pem()
local pub_pem = pk:write_pubkey_pem()
if test.debug then
  io.write(key_pem, pub_pem)
end

local pub = mbedtls.ecp.point():read_binary(group, test.secp256r1_1.pub_bin)
assert(pub:write_binary(group) == test.secp256r1_1.pub_bin)
local keypair = mbedtls.ecp.keypair():set_group(group):set_public_key(pub)
local pk = mbedtls.pk():setup(mbedtls.pk.ECKEY):set_ec(keypair)
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)

local key = mbedtls.mpi():read_binary(test.secp256r1_1.key_bin)
assert(key:bitlen() == 256)
assert(key:size() == 32)
assert(key:write_binary(32) == test.secp256r1_1.key_bin)
pk:set_ec(keypair:set_key(key))
assert(pk:write_key_pem() == test.secp256r1_1.key_pem)
assert(pk:write_pubkey_pem() == test.secp256r1_1.pub_pem)
