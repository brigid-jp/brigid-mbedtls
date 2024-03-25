#include "common.hpp"
#include <mbedtls/base64.h>
#include <cstddef>
#include <vector>

namespace brigid {
  namespace {
    void impl_encode(lua_State* L) {
      auto source = check_string_reference(L, 1);
      // 1byte余分に必要
      std::vector<unsigned char> buffer((source.size() + 2) / 3 * 4 + 1);
      std::size_t buffer_size = 0;
      check(mbedtls_base64_encode(
          buffer.data(),
          buffer.size(),
          &buffer_size,
          source.data(),
          source.size()));
      push_string_reference(L, string_reference(buffer.data(), buffer_size));
    }

    void impl_decode(lua_State* L) {
      auto source = check_string_reference(L, 1);
      std::vector<unsigned char> buffer((source.size() + 3) / 4 * 3);
      std::size_t buffer_size = 0;
      check(mbedtls_base64_decode(
          buffer.data(),
          buffer.size(),
          &buffer_size,
          source.data(),
          source.size()));
      push_string_reference(L, string_reference(buffer.data(), buffer_size));
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
