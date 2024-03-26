#include "common.hpp"
#include <mbedtls/version.h>
#include <array>

namespace brigid {
  namespace {
    void impl_get_number(lua_State* L) {
      auto version = mbedtls_version_get_number();
      lua_pushinteger(L, version);
    }

    void impl_get_string(lua_State* L) {
      std::array<char, 16> version;
      mbedtls_version_get_string(version.data());
      lua_pushstring(L, version.data());
    }

    void impl_get_string_full(lua_State* L) {
      std::array<char, 32> version;
      mbedtls_version_get_string_full(version.data());
      lua_pushstring(L, version.data());
    }
  }

  void initialize_version(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "get_number", function<impl_get_number>());
      set_field(L, -1, "get_string", function<impl_get_string>());
      set_field(L, -1, "get_string_full", function<impl_get_string_full>());
    }
    lua_setfield(L, -2, "version");
  }
}
