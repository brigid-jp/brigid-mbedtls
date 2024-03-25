#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecdh.hpp"
#include "ecp_keypair.hpp"

#include <cstddef>
#include <vector>

namespace brigid {
  namespace {
    using self_t = ecdh_t;

    void impl_setup(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto group_id = static_cast<mbedtls_ecp_group_id>(luaL_checkinteger(L, 2));
      check(mbedtls_ecdh_setup(self->get(), group_id));
    }

    void impl_get_params(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* key = ecp_keypair_t::check(L, 2);
      auto side = static_cast<mbedtls_ecdh_side>(luaL_checkinteger(L, 3));
      check(mbedtls_ecdh_get_params(self->get(), key->get(), side));
    }

    void impl_calc_secret(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* ctr_drbg = ctr_drbg_t::check(L, 3);
      std::vector<unsigned char> buffer(128);
      std::size_t buffer_size = 0;
      check(mbedtls_ecdh_calc_secret(self->get(), &buffer_size, buffer.data(), buffer.size(), mbedtls_ctr_drbg_random, ctr_drbg->get()));
      lua_pushlstring(L, reinterpret_cast<const char*>(buffer.data()), buffer_size);
    }
  }

  void initialize_ecdh(lua_State* L) {
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

      set_field(L, -1, "setup", function<impl_setup>());
      set_field(L, -1, "get_params", function<impl_get_params>());
      set_field(L, -1, "calc_secret", function<impl_calc_secret>());

      set_field(L, -1, "OURS", MBEDTLS_ECDH_OURS);
      set_field(L, -1, "THEIRS", MBEDTLS_ECDH_THEIRS);
    }
    lua_setfield(L, -2, "ecdh");
  }
}
