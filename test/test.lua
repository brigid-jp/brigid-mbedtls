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
