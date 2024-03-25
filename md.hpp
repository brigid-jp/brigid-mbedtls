#ifndef BRIGID_MBEDTLS_MD_HPP
#define BRIGID_MBEDTLS_MD_HPP

#include "common.hpp"
#include <mbedtls/md.h>

namespace brigid {
  class md_t : public context<md_t, mbedtls_md_context_t, mbedtls_md_init, mbedtls_md_free> {
  public:
    static constexpr const char* name = "brigid.mbedtls.md";
  };
}

#endif
