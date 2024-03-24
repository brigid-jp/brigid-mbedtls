#include "common.hpp"
#include "ecp_keypair.hpp"

#include <mbedtls/pk.h>

namespace brigid {
  class pk_t : public context<pk_t, mbedtls_pk_context, mbedtls_pk_init, mbedtls_pk_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.pk";
  };

  namespace {
    using self_t = pk_t;

    void impl_setup(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto type = luaL_checkinteger(L, 2);
      check(mbedtls_pk_setup(self->get(), mbedtls_pk_info_from_type(static_cast<mbedtls_pk_type_t>(type))));
    }

    void impl_import_ec(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* keypair = ecp_keypair_t::check(L, 2);
      auto* ec = mbedtls_pk_ec(*self->get());
      if (!ec) {
        luaL_argerror(L, 1, "EC context missing in the PK context");
      }
      check(mbedtls_ecp_export(
          keypair->get(),
          &ec->MBEDTLS_PRIVATE(grp),
          &ec->MBEDTLS_PRIVATE(d),
          &ec->MBEDTLS_PRIVATE(Q)));
    }

    void impl_export_ec(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* ec = mbedtls_pk_ec(*self->get());
      if (!ec) {
        luaL_argerror(L, 1, "EC context missing in the PK context");
      }
      auto* keypair = ecp_keypair_t::construct(L);
      check(mbedtls_ecp_export(
          ec,
          &keypair->get()->MBEDTLS_PRIVATE(grp),
          &keypair->get()->MBEDTLS_PRIVATE(d),
          &keypair->get()->MBEDTLS_PRIVATE(Q)));
    }



  }

  void initialize_pk(lua_State* L) {
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
      set_field(L, -1, "import_ec", function<impl_import_ec>());
      set_field(L, -1, "export_ec", function<impl_export_ec>());

      set_field(L, -1, "NONE", MBEDTLS_PK_NONE);
      set_field(L, -1, "RSA", MBEDTLS_PK_RSA);
      set_field(L, -1, "ECKEY", MBEDTLS_PK_ECKEY);
      set_field(L, -1, "ECKEY_DH", MBEDTLS_PK_ECKEY_DH);
      set_field(L, -1, "ECDSA", MBEDTLS_PK_ECDSA);
      set_field(L, -1, "RSA_ALT", MBEDTLS_PK_RSA_ALT);
      set_field(L, -1, "RSASSA_PSS", MBEDTLS_PK_RSASSA_PSS);
      set_field(L, -1, "OPAQUE", MBEDTLS_PK_OPAQUE);
    }
    lua_setfield(L, -2, "pk");
  }
}
