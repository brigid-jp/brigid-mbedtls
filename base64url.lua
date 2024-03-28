#! /usr/bin/env lua

local encoder = { [62] = "-", [63] = "_" }
for i = 0, 25 do
  encoder[i] = string.char(("A"):byte() + i)
end
for i = 26, 51 do
  encoder[i] = string.char(("a"):byte() + i - 26)
end
for i = 52, 61 do
  encoder[i] = string.char(("0"):byte() + i - 52)
end

io.write [[
#ifndef BRIGID_MBEDTLS_BASE64URL_HPP
#define BRIGID_MBEDTLS_BASE64URL_HPP

static constexpr const char encoder[] = {
]]

for y = 0, 7 do
  io.write "  "
  for x = 0, 7 do
    io.write(("'%s',"):format(encoder[y * 8 + x]))
    if x > 0 then
      io.write " "
    end
  end
  io.write "\n"
end

io.write [[
};

#endif
]]
