#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecp_keypair.hpp"
#include "pk.hpp"

#include <mbedtls/base64.h>

#include <vector>

#include <iostream>

namespace brigid {
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

    void impl_parse_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      std::size_t source_size = 0;
      const auto* source_data = reinterpret_cast<const unsigned char*>(luaL_checklstring(L, 2, &source_size));
      auto* ctr_drbg = ctr_drbg_t::check(L, 3);
      check(mbedtls_pk_parse_key(
          self->get(),
          source_data,
          source_size + 1,
          nullptr,
          0,
          mbedtls_ctr_drbg_random,
          ctr_drbg->get()));
    }

    // mbedtls-3.5.2のDERの最大長を調べた。RSAの公開鍵のことを考慮しても
    // 8192bytesあればPEMを格納できそうである。
    //
    // include/mbedtls/ecp.h
    //   MBEDTLS_ECP_MAX_BYTES = 66
    // library/pkwrite.h
    //   MBEDTLS_PK_MAX_ECC_BYTES = MBEDTLS_ECP_MAX_BYTES = 66
    //   MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES = MBEDTLS_PK_MAX_ECC_BYTES * 2 + 30 = 162
    //   MBEDTLS_PK_ECP_PRV_DER_MAX_BYTES = MBEDTLS_PK_MAX_ECC_BYTES * 3 + 29 = 227
    //
    // include/mbedtls/ecp.h
    //   MBEDTLS_MPI_MAX_SIZE = 1024
    // library/pkwrite.c
    //   MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES = MBEDTLS_MPI_MAX_SIZE * 2 + 38 = 2086
    //   MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES = MBEDTLS_MPI_MAX_SIZE * 5.5 + 48 = 5680

    void impl_write_key_pem(lua_State* L) {
      auto* self = self_t::check(L, 1);
      std::vector<unsigned char> buffer(8192);
      check(mbedtls_pk_write_key_pem(self->get(), buffer.data(), buffer.size()));
      lua_pushstring(L, reinterpret_cast<const char*>(buffer.data()));
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
      set_field(L, -1, "parse_key", function<impl_parse_key>());
      set_field(L, -1, "write_key_pem", function<impl_write_key_pem>());

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
