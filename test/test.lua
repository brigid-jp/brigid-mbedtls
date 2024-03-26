local mbedtls = require "brigid.mbedtls"
local test = require "test"

local function setup_pk_none()
  return mbedtls.pk():setup(mbedtls.pk.NONE)
end

assert(mbedtls.get_runtime_error_policy() == "fail")
test.assume_fail(setup_pk_none)

assert(mbedtls.set_runtime_error_policy "error")
assert(mbedtls.get_runtime_error_policy() == "error")
test.assume_error(setup_pk_none)

assert(mbedtls.set_runtime_error_policy())
assert(mbedtls.get_runtime_error_policy() == nil)
test.assume_fail(setup_pk_none)

assert(mbedtls.set_runtime_error_policy "fail")
assert(mbedtls.get_runtime_error_policy() == "fail")
test.assume_fail(setup_pk_none)

assert(debug.getregistry()["brigid.mbedtls.runtime_error_policy"] == "fail")

local version = mbedtls.get_version()
if test.debug then
  print("version: "..version)
end
assert(version:match "^%d+%.%d+$")

-- 0x03 05 02 00
local n = mbedtls.version.get_number()
local s = mbedtls.version.get_string()
local f = mbedtls.version.get_string_full()
if test.debug then
  print(("number: 0x%08X"):format(n))
  print("string: "..s)
  print("string_full: "..f)
end
local x, y, z = assert(s:match "^(%d+)%.(%d+)%.(%d+)$")
assert(n == x * 0x1000000 + y * 0x10000 + z * 0x100)
assert("Mbed TLS "..s == f)
