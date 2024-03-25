#ifndef BRIGID_MBEDTLS_PK_HPP
#define BRIGID_MBEDTLS_PK_HPP

#include "common.hpp"
#include <mbedtls/pk.h>

namespace brigid {
  class pk_t : public context<pk_t, mbedtls_pk_context, mbedtls_pk_init, mbedtls_pk_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.pk";
  };
}

#endif
