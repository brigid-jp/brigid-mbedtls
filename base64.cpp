#include "common.hpp"
#include <mbedtls/base64.h>
#include <cstddef>
#include <vector>

namespace brigid {
  namespace {
    void impl_encode(lua_State* L) {
      auto input = check_string_reference(L, 1);
      // 1byte余分に必要
      std::vector<unsigned char> output((input.size() + 2) / 3 * 4 + 1);
      std::size_t output_size = 0;
      check(mbedtls_base64_encode(
          output.data(),
          output.size(),
          &output_size,
          input.data(),
          input.size()));
      push_string_reference(L, string_reference(output.data(), output_size));
    }

    void impl_decode(lua_State* L) {
      auto input = check_string_reference(L, 1);
      std::vector<unsigned char> output((input.size() + 3) / 4 * 3);
      std::size_t output_size = 0;
      check(mbedtls_base64_decode(
          output.data(),
          output.size(),
          &output_size,
          input.data(),
          input.size()));
      push_string_reference(L, string_reference(output.data(), output_size));
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
