#include "common.hpp"
#include "ecp_group.hpp"
#include "ecp_point.hpp"
#include <cstddef>
#include <array>

namespace brigid {
  namespace {
    using self_t = ecp_point_t;

    void impl_write_binary(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* group = ecp_group_t::check(L, 2);
      auto format = luaL_optinteger(L, 3, MBEDTLS_ECP_PF_UNCOMPRESSED);
      std::array<unsigned char, 128> buffer;
      std::size_t buffer_size = 0;
      check(mbedtls_ecp_point_write_binary(
          group->get(),
          self->get(),
          format,
          &buffer_size,
          buffer.data(),
          buffer.size()));
      push_string_reference(L, string_reference(buffer.data(), buffer_size));
    }

    void impl_read_binary(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* group = ecp_group_t::check(L, 2);
      auto source = check_string_reference(L, 3);
      check(mbedtls_ecp_point_read_binary(
          group->get(),
          self->get(),
          source.data(),
          source.size()));
    }
  }

  void initialize_ecp_point(lua_State* L) {
    lua_newtable(L);
    {
      luaL_newmetatable(L, self_t::name);
      lua_pushvalue(L, -2);
      lua_setfield(L, -2, "__index");
      set_field(L, -1, "__gc", self_t::destructor());
      lua_pop(L, 1);

      lua_newtable(L);
      set_field(L, -1, "__call", self_t::constructor());
      lua_setmetatable(L, -2);

      set_field(L, -1, "write_binary", function<impl_write_binary>());
      set_field(L, -1, "read_binary", function<impl_read_binary>());
    }
    lua_setfield(L, -2, "point");
  }
}
