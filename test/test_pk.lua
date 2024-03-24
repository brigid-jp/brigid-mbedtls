local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local pk = mbedtls.pk()

local result, message = pk:setup(-1)
if debug then
  print(message)
end
assert(not result)

assert(pk:setup(pk.ECKEY))
