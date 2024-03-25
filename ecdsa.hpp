#ifndef BRIGID_MBEDTLS_ECDSA_HPP
#define BRIGID_MBEDTLS_ECDSA_HPP

#include "common.hpp"
#include <mbedtls/ecdsa.h>

namespace brigid {
  class ecdsa_t : public context<
    ecdsa_t,
    mbedtls_ecdsa_context,
    mbedtls_ecdsa_init,
    mbedtls_ecdsa_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ecdsa";
  };
}

#endif
