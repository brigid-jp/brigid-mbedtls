#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecdsa.hpp"
#include "ecp_keypair.hpp"

#include <cstddef>
#include <vector>

namespace brigid {
  namespace {
    using self_t = ecdsa_t;

    void impl_from_keypair(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* keypair = ecp_keypair_t::check(L, 2);
      check(mbedtls_ecdsa_from_keypair(self->get(), keypair->get()));
    }

    void impl_sign_det_ext(lua_State* L) {
      auto* self = self_t::check(L, 1);
    }

    // check(mbedtls_ecdsa_sign_det_ext(
    //     &ecdsa->MBEDTLS_PRIVATE(grp),
    //     r.get(),
    //     s.get(),
    //     &ecdsa->MBEDTLS_PRIVATE(d),
    //     hash.data(),
    //     hash.size(),
    //     MBEDTLS_MD_SHA256,
    //     mbedtls_ctr_drbg_random,
    //     ctr_drbg.get()));



  }

  void initialize_ecdsa(lua_State* L) {
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
    }
    lua_setfield(L, -2, "ecdsa");
  }
}
