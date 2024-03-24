#ifndef BRIGID_MBEDTLS_ENTROPY_HPP
#define BRIGID_MBEDTLS_ENTROPY_HPP

#include "common.hpp"

#include <mbedtls/entropy.h>

namespace brigid {
  class entropy : public context<mbedtls_entropy_context, mbedtls_entropy_init, mbedtls_entropy_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.entropy";
  };
}

#endif
