#include "common.hpp"

#include <mbedtls/error.h>

#include <array>

namespace brigid {
  void check(int result) {
    if (result != 0) {
      // mbedtls-3.5.2のerror.cを調べたところ、134文字が最長だった。
      std::array<char, 256> buffer;
      mbedtls_strerror(result, buffer.data(), buffer.size());
      throw std::runtime_error(buffer.data());
    }
  }
}
