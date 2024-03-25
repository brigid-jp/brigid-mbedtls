#include "common.hpp"

#include <mbedtls/error.h>

#include <array>

namespace brigid {
  void check(int result) {
    if (result != 0) {
      // mbedtls-3.5.2のlibrary/error.cを調べたところ、エラーメッセージの最大長
      // は134bytesだった。
      std::array<char, 257> buffer;
      mbedtls_strerror(result, buffer.data(), buffer.size());
      throw std::runtime_error(buffer.data());
    }
  }
}
