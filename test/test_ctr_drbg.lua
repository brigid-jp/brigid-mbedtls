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

assert(debug.getregistry()["brigid.mbedtls.entropy.default"] == nil)
assert(debug.getregistry()["brigid.mbedtls.ctr_drbg.default"] == nil)

local default_entropy = mbedtls.entropy.get_default()
assert(debug.getregistry()["brigid.mbedtls.entropy.default"] == default_entropy)
if test.debug then
  print(default_entropy)
end

local default_ctr_drbg = mbedtls.ctr_drbg.get_default()
assert(debug.getregistry()["brigid.mbedtls.ctr_drbg.default"] == default_ctr_drbg)
if test.debug then
  print(default_ctr_drbg)
end

if test.debug then
  print("e1", default_entropy)
  print("e2", debug.getregistry()["brigid.mbedtls.entropy.default"])
  print("e3", mbedtls.entropy.get_default())
  print("e4", debug.getregistry()["brigid.mbedtls.entropy.default"])
end
assert(debug.getregistry()["brigid.mbedtls.entropy.default"] == default_entropy)
