#ifndef BRIGID_MBEDTLS_ECDH_HPP
#define BRIGID_MBEDTLS_ECDH_HPP

#include "common.hpp"
#include <mbedtls/ecdh.h>

namespace brigid {
  class ecdh_t : public context<ecdh_t, mbedtls_ecdh_context, mbedtls_ecdh_init, mbedtls_ecdh_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.ecdh";
  };
}

#endif
