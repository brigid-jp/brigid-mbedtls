local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local n = 16

local entropy = mbedtls.entropy()
local data = entropy:func(n)
assert(#data == n)
if test.debug then
  print(("%02X"):rep(n):format(string.byte(data, 1, n)))
end

local ctr_drbg = mbedtls.ctr_drbg()
ctr_drbg:seed(entropy)
collectgarbage()
collectgarbage()
local data = ctr_drbg:random(n)
assert(#data == n)
if test.debug then
  print(("%02X"):rep(n):format(string.byte(data, 1, n)))
end
