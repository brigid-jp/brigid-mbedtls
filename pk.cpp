#include "common.hpp"
#include "ctr_drbg.hpp"
#include "ecp_keypair.hpp"
#include "pk.hpp"
#include <array>

namespace brigid {
  namespace {
    using self_t = pk_t;

    void impl_setup(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto pk_type = static_cast<mbedtls_pk_type_t>(luaL_checkinteger(L, 2));
      check(mbedtls_pk_setup(self->get(), mbedtls_pk_info_from_type(pk_type)));
    }

    void impl_set_ec(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* src = ecp_keypair_t::check(L, 2);
      auto* dst = mbedtls_pk_ec(*self->get());
      if (!dst) {
        luaL_argerror(L, 1, "EC context missing in the PK context");
        return;
      }
      check(mbedtls_ecp_export(
          src->get(),
          &dst->MBEDTLS_PRIVATE(grp),
          &dst->MBEDTLS_PRIVATE(d),
          &dst->MBEDTLS_PRIVATE(Q)));
    }

    void impl_get_ec(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto* src = mbedtls_pk_ec(*self->get());
      if (!src) {
        luaL_argerror(L, 1, "EC context missing in the PK context");
        return;
      }
      auto* dst = ecp_keypair_t::construct(L);
      check(mbedtls_ecp_export(
          src,
          &dst->get()->MBEDTLS_PRIVATE(grp),
          &dst->get()->MBEDTLS_PRIVATE(d),
          &dst->get()->MBEDTLS_PRIVATE(Q)));
    }

    void impl_parse_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto key = check_string_reference(L, 2);
      auto* ctr_drbg = ctr_drbg_t::optional(L, 3);
      check(mbedtls_pk_parse_key(
          self->get(),
          key.data(),
          key.size() + 1,
          nullptr,
          0,
          mbedtls_ctr_drbg_random,
          ctr_drbg->get()));
    }

    void impl_parse_public_key(lua_State* L) {
      auto* self = self_t::check(L, 1);
      auto public_key = check_string_reference(L, 2);
      check(mbedtls_pk_parse_public_key(
          self->get(),
          public_key.data(),
          public_key.size() + 1));
    }

    // mbedtls-3.5.2のDERの最大長を調べた。RSAの秘密鍵で4096bytes、公開鍵で
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
      std::array<unsigned char, 4096> output;
      check(mbedtls_pk_write_key_pem(self->get(), output.data(), output.size()));
      lua_pushstring(L, reinterpret_cast<const char*>(output.data()));
    }

    void impl_write_pubkey_pem(lua_State* L) {
      auto* self = self_t::check(L, 1);
      std::array<unsigned char, 8192> output;
      check(mbedtls_pk_write_pubkey_pem(self->get(), output.data(), output.size()));
      lua_pushstring(L, reinterpret_cast<const char*>(output.data()));
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
      set_field(L, -1, "set_ec", function<impl_set_ec>());
      set_field(L, -1, "get_ec", function<impl_get_ec>());
      set_field(L, -1, "parse_key", function<impl_parse_key>());
      set_field(L, -1, "parse_public_key", function<impl_parse_public_key>());
      set_field(L, -1, "write_key_pem", function<impl_write_key_pem>());
      set_field(L, -1, "write_pubkey_pem", function<impl_write_pubkey_pem>());

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
