local mbedtls = require "brigid.mbedtls"
mbedtls.set_runtime_error_policy "error"

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
}

for i, v in ipairs(data) do
  assert(mbedtls.base64.encode(v[1]) == v[2])
  assert(mbedtls.base64.decode(v[2]) == v[1])
end

local function encode_base64url(input)
  local output = mbedtls.base64.encode(input)
  return (output:gsub("[+/]", { ["+"] = "-", ["/"] = "_" }):gsub("=+$", ""))
end

local function decode_base64url(input)
  input = input:gsub("[%-_]", { ["-"] = "+", ["_"] = "/" })
  return mbedtls.base64.decode(input..("="):rep(-#input % 4))
end

local data = {
  { string.char(0xEF, 0xBB, 0xBF), "77u_" }; -- U+FEFF ZERO WIDTH NO-BREAK SPACE
  { string.char(0xF0, 0x9F, 0x8D, 0xA3), "8J-Now" }; -- U+1F363 SUSHI
}

for i, v in ipairs(data) do
  assert(encode_base64url(v[1]) == v[2])
  assert(decode_base64url(v[2]) == v[1])
end

