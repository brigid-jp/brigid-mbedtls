#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecp_group.hpp"
#include "ecp_keypair.hpp"
#include "ecp_point.hpp"
#include "mpi.hpp"

namespace brigid {
  namespace {
    using self_t = ecp_keypair_t;

    void impl_gen_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto group_id = static_cast<mbedtls_ecp_group_id>(luaL_checkinteger(L, 2));
      auto* ctr_drbg = ctr_drbg_t::check(L, 3);
      check(mbedtls_ecp_gen_key(
          group_id,
          self->get(),
          mbedtls_ctr_drbg_random,
          ctr_drbg->get()));
    }

    void impl_set_group(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* source = ecp_group_t::check(L, 2);
      check(mbedtls_ecp_group_copy(&self->get()->MBEDTLS_PRIVATE(grp), source->get()));
    }

    void impl_get_group(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* result = ecp_group_t::construct(L);
      check(mbedtls_ecp_group_copy(result->get(), &self->get()->MBEDTLS_PRIVATE(grp)));
    }

    void impl_set_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* source = mpi_t::check(L, 2);
      check(mbedtls_mpi_copy(&self->get()->MBEDTLS_PRIVATE(d), source->get()));
    }

    void impl_get_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* result = mpi_t::construct(L);
      check(mbedtls_mpi_copy(result->get(), &self->get()->MBEDTLS_PRIVATE(d)));
    }

    void impl_set_public_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* source = ecp_point_t::check(L, 2);
      check(mbedtls_ecp_copy(&self->get()->MBEDTLS_PRIVATE(Q), source->get()));
    }

    void impl_get_public_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* result = ecp_point_t::construct(L);
      check(mbedtls_ecp_copy(result->get(), &self->get()->MBEDTLS_PRIVATE(Q)));
    }
  }

  void initialize_ecp_keypair(lua_State* L) {
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

      set_field(L, -1, "gen_key", function<impl_gen_key>());
      set_field(L, -1, "set_group", function<impl_set_group>());
      set_field(L, -1, "get_group", function<impl_get_group>());
      set_field(L, -1, "set_key", function<impl_set_key>());
      set_field(L, -1, "get_key", function<impl_get_key>());
      set_field(L, -1, "set_public_key", function<impl_set_public_key>());
      set_field(L, -1, "get_public_key", function<impl_get_public_key>());
    }
    lua_setfield(L, -2, "keypair");
  }
}
