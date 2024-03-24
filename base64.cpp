#include "common.hpp"

#include <mbedtls/base64.h>

#include <vector>

namespace brigid {
  namespace {
    void impl_encode(lua_State* L) {
      std::size_t source_size = 0;
      const auto* source_data = reinterpret_cast<const unsigned char*>(luaL_checklstring(L, 1, &source_size));
      // 1byte余分に必要
      std::vector<unsigned char> buffer((source_size + 2) / 3 * 4 + 1);
      std::size_t buffer_size = 0;
      check(mbedtls_base64_encode(buffer.data(), buffer.size(), &buffer_size, source_data, source_size));
      lua_pushlstring(L, reinterpret_cast<const char*>(buffer.data()), buffer_size);
    }

    void impl_decode(lua_State* L) {
      std::size_t source_size = 0;
      const auto* source_data = reinterpret_cast<const unsigned char*>(luaL_checklstring(L, 1, &source_size));
      std::vector<unsigned char> buffer((source_size + 3) / 4 * 3 + 1);
      std::size_t buffer_size = 0;
      check(mbedtls_base64_decode(buffer.data(), buffer.size(), &buffer_size, source_data, source_size));
      lua_pushlstring(L, reinterpret_cast<const char*>(buffer.data()), buffer_size);
    }
  }

  void initialize_base64(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "encode", function<impl_encode>());
      set_field(L, -1, "decode", function<impl_decode>());
    }
    lua_setfield(L, -2, "base64");
  }
}
