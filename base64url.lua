#! /usr/bin/env lua

local encoder = {
  [62] = "-";
  [63] = "_";
}
local decoder = {
  [("-"):byte()] = 62;
  [("_"):byte()] = 63;
}

for i = 0, 25 do
  local v = ("A"):byte() + i
  encoder[i] = string.char(v)
  decoder[v] = i
end
for i = 26, 51 do
  local v = ("a"):byte() + i - 26
  encoder[i] = string.char(v)
  decoder[v] = i
end
for i = 52, 61 do
  local v = ("0"):byte() + i - 52
  encoder[i] = string.char(v)
  decoder[v] = i
end

decoder[("\t"):byte()] = 0x40
decoder[("\n"):byte()] = 0x40
decoder[("\v"):byte()] = 0x40
decoder[("\f"):byte()] = 0x40
decoder[("\r"):byte()] = 0x40
decoder[(" "):byte()] = 0x40
decoder[("="):byte()] = 0x41
for i = 0, 127 do
  if not decoder[i] then
    decoder[i] = 0x42;
  end
end

io.write [[
#ifndef BRIGID_MBEDTLS_BASE64URL_HPP
#define BRIGID_MBEDTLS_BASE64URL_HPP

namespace brigid {
  namespace {
    static constexpr const char encoder[] = {
]]

for y = 0, 7 do
  io.write "      "
  for x = 0, 7 do
    if x > 0 then
      io.write " "
    end
    io.write(("'%s',"):format(encoder[y * 8 + x]))
  end
  io.write "\n"
end

io.write [[
    };

    static constexpr const char decoder[] = {
]]

for y = 0, 15 do
  io.write "      "
  for x = 0, 7 do
    if x > 0 then
      io.write " "
    end
    io.write(("0x%02X,"):format(decoder[y * 8 + x]))
  end
  io.write "\n"
end

io.write [[
    };
  }
}

#endif
]]
