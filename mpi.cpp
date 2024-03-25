#include "common.hpp"
#include "mpi.hpp"
#include <vector>

namespace brigid {
  namespace {
    using self_t = mpi_t;

    void impl_bitlen(lua_State* L) {
      auto* self = self_t::check(L, 1);
      lua_pushinteger(L, mbedtls_mpi_bitlen(self->get()));
    }

    void impl_size(lua_State* L) {
      auto* self = self_t::check(L, 1);
      lua_pushinteger(L, mbedtls_mpi_size(self->get()));
    }

    void impl_read_binary(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto source = check_string_reference(L, 2);
      check(mbedtls_mpi_read_binary(self->get(), source.data(), source.size()));
    }

    void impl_write_binary(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto size = luaL_checkinteger(L, 2);
      if (size < 0) {
        luaL_argerror(L, 2, "out of bounds");
        return;
      }
      std::vector<unsigned char> buffer(size);
      check(mbedtls_mpi_write_binary(self->get(), buffer.data(), buffer.size()));
      push_string_reference(L, buffer);
    }
  }

  void initialize_mpi(lua_State* L) {
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

      set_field(L, -1, "bitlen", function<impl_bitlen>());
      set_field(L, -1, "size", function<impl_size>());
      set_field(L, -1, "read_binary", function<impl_read_binary>());
      set_field(L, -1, "write_binary", function<impl_write_binary>());
    }
    lua_setfield(L, -2, "mpi");
  }
}
