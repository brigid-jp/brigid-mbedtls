local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

assert(mbedtls.get_runtime_error_policy() == "fail")

local result, message = mbedtls.pk():setup(mbedtls.pk.NONE)
if debug then
  print(message)
end
assert(not result)

assert(mbedtls.set_runtime_error_policy "error")
local result, message = pcall(function ()
  mbedtls.pk():setup(mbedtls.pk.NONE)
end)
if debug then
  print(message)
end
assert(not result)

assert(mbedtls.set_runtime_error_policy())
local result, message = mbedtls.pk():setup(mbedtls.pk.NONE)
if debug then
  print(message)
end
assert(not result)
