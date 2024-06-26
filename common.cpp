#include "common.hpp"
#include <mbedtls/error.h>
#include <cstring>
#include <array>

namespace brigid {
  namespace {
    static constexpr const char* registry_key = "brigid.mbedtls.runtime_error_policy";

    void impl_get_version(lua_State* L) {
      static constexpr const char* version =
#include "brigid-mbedtls-version"
      ;
      lua_pushstring(L, version);
    }

    void impl_set_runtime_error_policy(lua_State* L) {
      lua_pushvalue(L, 1);
      lua_setfield(L, LUA_REGISTRYINDEX, registry_key);
    }

    void impl_get_runtime_error_policy(lua_State* L) {
      lua_getfield(L, LUA_REGISTRYINDEX, registry_key);
    }
  }

  bool runtime_error_policy_is_error(lua_State* L) {
    stack_guard guard(L);

    lua_getfield(L, LUA_REGISTRYINDEX, registry_key);
    std::size_t size = 0;
    if (const auto* data = lua_tolstring(L, -1, &size)) {
      return size == 5 && strncmp(data, "error", 5) == 0;
    } else {
      return false;
    }
  }

  void check(int result) {
    if (result != 0) {
      // mbedtls-3.5.2のlibrary/error.cを調べたところ、エラーメッセージの最大長
      // は134bytesだった。
      std::array<char, 256> buffer;
      mbedtls_strerror(result, buffer.data(), buffer.size());
      throw std::runtime_error(buffer.data());
    }
  }

  void initialize_common(lua_State* L) {
    lua_pushstring(L, "fail");
    lua_setfield(L, LUA_REGISTRYINDEX, registry_key);

    set_field(L, -1, "get_version", function<impl_get_version>());
    set_field(L, -1, "set_runtime_error_policy", function<impl_set_runtime_error_policy>());
    set_field(L, -1, "get_runtime_error_policy", function<impl_get_runtime_error_policy>());
  }
}
