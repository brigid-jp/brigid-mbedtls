#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecp_group.hpp"
#include "ecp_point.hpp"
#include "mpi.hpp"
#include <mbedtls/ecdsa.h>
#include <mbedtls/md.h>

namespace brigid {
  namespace {
    void impl_sign_det_ext(lua_State* L) {
      auto* group = ecp_group_t::check(L, 1);
      auto* key = mpi_t::check(L, 2);
      auto hash = check_string_reference(L, 3);
      auto md_algorithm = static_cast<mbedtls_md_type_t>(luaL_checkinteger(L, 4));
      auto* ctr_drbg = ctr_drbg_t::optional(L, 5);
      auto* r = mpi_t::construct(L);
      auto* s = mpi_t::construct(L);
      check(mbedtls_ecdsa_sign_det_ext(
          group->get(),
          r->get(),
          s->get(),
          key->get(),
          hash.data(),
          hash.size(),
          md_algorithm,
          mbedtls_ctr_drbg_random,
          ctr_drbg->get()));
    }

    void impl_verify(lua_State* L) {
      auto* group = ecp_group_t::check(L, 1);
      auto hash = check_string_reference(L, 2);
      auto* public_key = ecp_point_t::check(L, 3);
      auto* r = mpi_t::check(L, 4);
      auto* s = mpi_t::check(L, 5);
      check(mbedtls_ecdsa_verify(
          group->get(),
          hash.data(),
          hash.size(),
          public_key->get(),
          r->get(),
          s->get()));
    }
  }

  void initialize_ecdsa(lua_State* L) {
    lua_newtable(L);
    {
      set_field(L, -1, "sign_det_ext", function<impl_sign_det_ext>());
      set_field(L, -1, "verify", function<impl_verify>());
    }
    lua_setfield(L, -2, "ecdsa");
  }
}
