local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

do
  local group = mbedtls.ecp.group()
  local result, message = group:load(mbedtls.ecp.DP_NONE)
  if debug then
    print(message)
  end
  assert(not result)
  assert(group:load(mbedtls.ecp.DP_SECP256R1))
end


