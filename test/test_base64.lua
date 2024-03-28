local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"
local test = require "test"

local data = {
  { "", "" };
  { "f", "Zg==" };
  { "fo", "Zm8=" };
  { "foo", "Zm9v" };
  { "foob", "Zm9vYg==" };
  { "fooba", "Zm9vYmE=" };
  { "foobar", "Zm9vYmFy" };
  { ("foobar"):rep(512), ("Zm9vYmFy"):rep(512) };
  { "日本語", "5pel5pys6Kqe" };
  { ("日本語"):rep(512), ("5pel5pys6Kqe"):rep(512) };
  { string.char(0xEF, 0xBB, 0xBF), "77u/" }; -- U+FEFF ZERO WIDTH NO-BREAK SPACE
  { string.char(0xF0, 0x9F, 0x8D, 0xA3), "8J+Now==" }; -- U+1F363 SUSHI
}

for i, v in ipairs(data) do
  assert(mbedtls.base64.encode(v[1]) == v[2])
  assert(mbedtls.base64.decode(v[2]) == v[1])
end

local data = {
  { "", "" };
  { "f", "Zg" };
  { "fo", "Zm8" };
  { "foo", "Zm9v" };
  { "foob", "Zm9vYg" };
  { "fooba", "Zm9vYmE" };
  { "foobar", "Zm9vYmFy" };
  { ("foobar"):rep(512), ("Zm9vYmFy"):rep(512) };
  { "日本語", "5pel5pys6Kqe" };
  { ("日本語"):rep(512), ("5pel5pys6Kqe"):rep(512) };
  { string.char(0xEF, 0xBB, 0xBF), "77u_" }; -- U+FEFF ZERO WIDTH NO-BREAK SPACE
  { string.char(0xF0, 0x9F, 0x8D, 0xA3), "8J-Now" }; -- U+1F363 SUSHI
}

for i, v in ipairs(data) do
  assert(mbedtls.base64url.encode(v[1]) == v[2])
  assert(mbedtls.base64url.decode(v[2]) == v[1])
end

assert(mbedtls.base64url.decode("Z\tm\n9\vv\fY\rm F\r\ny===") == "foobar")
assert(mbedtls.base64url.decode("=Zm9v=") == "")

test.assume_error(mbedtls.base64url.decode, "77u/")
test.assume_error(mbedtls.base64url.decode, "8J+Now")
