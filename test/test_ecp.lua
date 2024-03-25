local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local entropy = mbedtls.entropy()
local ctr_drbg = mbedtls.ctr_drbg():seed(entropy)

do
  local group = mbedtls.ecp.group()
  local result, message = group:load(mbedtls.ecp.DP_NONE)
  if debug then
    print(message)
  end
  assert(not result)
  assert(group:load(mbedtls.ecp.DP_SECP256R1))
end

do
  local keypair = mbedtls.ecp.keypair()
  keypair:gen_key(mbedtls.ecp.DP_SECP256R1, ctr_drbg)

  local pk = mbedtls.pk()
  assert(pk:setup(mbedtls.pk.ECKEY))
  assert(pk:set_ec(keypair))

  local key_pem = assert(pk:write_key_pem())
  local pubkey_pem = assert(pk:write_pubkey_pem())

  if debug then
    io.write(key_pem)
    io.write(pubkey_pem)
  end
end


