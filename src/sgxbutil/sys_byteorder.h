// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This header defines cross-platform ByteSwap() implementations for 16, 32 and
// 64-bit values, and NetToHostXX() / HostToNextXX() functions equivalent to
// the traditional ntohX() and htonX() functions.
// Use the functions defined here rather than using the platform-specific
// functions directly.

#ifndef SGX_BUTIL_SYS_BYTEORDER_H_
#define SGX_BUTIL_SYS_BYTEORDER_H_

//- TODO: 先暂时注释掉，否则调试时basictypes.h里面的常量会报重复定义的错误
//- 而且似乎这个头文件也不是必须的(里面有写到DEPRECATED)？
#include "sgxbutil/basictypes.h"

//- We already know intel uses little endian.
// #include "butil/build_config.h"

//- OpenEnclave supports following headers. (Linux only)
#include <arpa/inet.h>
#include <byteswap.h> // for bswap_* 

namespace sgxbutil {

inline uint16_t ByteSwap(uint16_t x) { return bswap_16(x); }
inline uint32_t ByteSwap(uint32_t x) { return bswap_32(x); }
inline uint64_t ByteSwap(uint64_t x) { return bswap_64(x); }

// Converts the bytes in |x| from host order (endianness) to little endian, and
// returns the result.
inline uint16_t ByteSwapToLE16(uint16_t x) {
  return x;
}
inline uint32_t ByteSwapToLE32(uint32_t x) {
  return x;
}
inline uint64_t ByteSwapToLE64(uint64_t x) {
  return x;
}

// Converts the bytes in |x| from network to host order (endianness), and
// returns the result.
inline uint16_t NetToHost16(uint16_t x) {
  return ByteSwap(x);
}
inline uint32_t NetToHost32(uint32_t x) {
  return ByteSwap(x);
}
inline uint64_t NetToHost64(uint64_t x) {
  return ByteSwap(x);

}

// Converts the bytes in |x| from host to network order (endianness), and
// returns the result.
inline uint16_t HostToNet16(uint16_t x) {
  return ByteSwap(x);
}
inline uint32_t HostToNet32(uint32_t x) {
  return ByteSwap(x);
}
inline uint64_t HostToNet64(uint64_t x) {
  return ByteSwap(x);
}

}  // namespace sgxbutil

#endif  // SGX_BUTIL_SYS_BYTEORDER_H_
