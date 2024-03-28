#include "common.hpp"
#include "base64url.hpp"
#include <cstdint>

namespace brigid {
  namespace {
    void impl_encode(lua_State* L) {
      auto input = check_string_reference(L, 1);

      luaL_Buffer output = {};
      luaL_buffinit(L, &output);

      const auto* ptr = input.data();
      const auto* end = ptr + input.size();
      std::uint32_t v = 0;
      std::size_t n = 0;
      for (; ptr != end; ++ptr) {
        v <<= 8;
        v |= *ptr;
        if (++n == 3) {
          luaL_addchar(&output, encoder[v >> 18]);
          luaL_addchar(&output, encoder[v >> 12 & 0x3F]);
          luaL_addchar(&output, encoder[v >> 6 & 0x3F]);
          luaL_addchar(&output, encoder[v & 0x3F]);
          v = 0;
          n = 0;
        }
      }

      switch (n) {
        case 2:
          luaL_addchar(&output, encoder[v >> 10]);
          luaL_addchar(&output, encoder[v >> 4 & 0x3F]);
          luaL_addchar(&output, encoder[v << 2 & 0x3F]);
          break;
        case 1:
          luaL_addchar(&output, encoder[v >> 2]);
          luaL_addchar(&output, encoder[v << 4 & 0x3F]);
          break;
      }

      luaL_pushresult(&output);
    }

    void impl_decode(lua_State* L) {
      auto input = check_string_reference(L, 1);

      luaL_Buffer output = {};
      luaL_buffinit(L, &output);

      const auto* ptr = input.data();
      const auto* end = ptr + input.size();
      std::uint32_t v = 0;
      std::size_t n = 0;
      for (; ptr != end; ++ptr) {
        std::uint32_t c = *ptr;
        if (c > 0x7F) {
          luaL_argerror(L, 1, "invalid character");
          return;
        }
        std::uint32_t u = decoder[c];

        if (u == 0x42) {
          luaL_argerror(L, 1, "invalid character");
          return;
        } else if (u == 0x41) {
          break;
        } else if (u == 0x40) {
          continue;
        }

        v <<= 6;
        v |= u;
        if (++n == 4) {
          luaL_addchar(&output, v >> 16);
          luaL_addchar(&output, v >> 8 & 0xFF);
          luaL_addchar(&output, v & 0xFF);
          v = 0;
          n = 0;
        }
      }

      switch (n) {
        case 3:
          luaL_addchar(&output, v >> 10);
          luaL_addchar(&output, v >> 2 & 0xFF);
          break;
        case 2:
          luaL_addchar(&output, v >> 4);
          break;
      }

      luaL_pushresult(&output);
    }
  }

  void initialize_base64url(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "encode", function<impl_encode>());
      set_field(L, -1, "decode", function<impl_decode>());
    }
    lua_setfield(L, -2, "base64url");
  }
}
