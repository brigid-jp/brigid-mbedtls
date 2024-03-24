local mbedtls = require "brigid.mbedtls"

local debug = (tonumber(os.getenv "BRIGID_DEBUG") or 0) > 0

local data = {
  { "", "" };
  { "f", "Zg==" };
  { "fo", "Zm8=" };
  { "foo", "Zm9v" };
}

for i, v in ipairs(data) do
  if debug then
    print(v[1], v[2])
  end
  assert(mbedtls.base64.encode(v[1]) == v[2])
  assert(mbedtls.base64.decode(v[2]) == v[1])
end

local function encode_base64url(source)
  local buffer = mbedtls.base64.encode(source)
  return (buffer:gsub("%+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function decode_base64url(source)
  local buffer = source:gsub("%-", "+"):gsub("_", "/")
  return mbedtls.base64.decode(buffer..("="):rep(-#buffer % 4))
end

local data = {
  { string.char(0xEF, 0xBB, 0xBF), "77u_" }; -- U+FEFF ZERO WIDTH NO-BREAK SPACE
  { string.char(0xF0, 0x9F, 0x8D, 0xA3), "8J-Now" }; -- U+1F363 SUSHI
}

for i, v in ipairs(data) do
  if debug then
    print(v[1], v[2])
  end
  assert(encode_base64url(v[1]) == v[2])
  assert(decode_base64url(v[2]) == v[1])
end
