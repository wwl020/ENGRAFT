// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//

//
// Deal with the differences between Microsoft and GNU implemenations
// of hash_map. Allows all platforms to use |butil::hash_map| and
// |butil::hash_set|.
//  eg:
//   butil::hash_map<int, std::string> my_map;
//   butil::hash_set<int> my_set;
//
// NOTE: It is an explicit non-goal of this class to provide a generic hash
// function for pointers.  If you want to hash a pointers to a particular class,
// please define the template specialization elsewhere (for example, in its
// header file) and keep it specific to just pointers to that class.  This is
// because identity hashes are not desirable for all types that might show up
// in containers as pointers.

//- TODO: 可能会和原有的hash_tables.h冲突 因为
//- BUTIL_HASH_NAMESPACE 都是 __gnu_cxx，所以注释在 BUTIL_HASH_NAMESPACE 里面的代码
#ifndef SGX_BUTIL_CONTAINERS_HASH_TABLES_H_
#define SGX_BUTIL_CONTAINERS_HASH_TABLES_H_

#include <utility>
//- TODO: May not need basictypes.h here
#include "sgxbutil/basictypes.h"
// #include "butil/strings/string16.h"
// #include "butil/build_config.h"
#include "sgxbutil/third_party/murmurhash3/murmurhash3.h"   // fmix64
//- TODO: Include this header for temporary fix
// #include "butil/containers/hash_tables.h"

//- Compiler is gcc/clang
#define BUTIL_HASH_NAMESPACE __gnu_cxx

// This is a hack to disable the gcc 4.4 warning about hash_map and hash_set
// being deprecated.  We can get rid of this when we upgrade to VS2008 and we
// can use <tr1/unordered_map> and <tr1/unordered_set>.
#ifdef __DEPRECATED
#define CHROME_OLD__DEPRECATED __DEPRECATED
#undef __DEPRECATED
#endif

#include <ext/hash_map>
#include <ext/hash_set>

#include <string>

#ifdef CHROME_OLD__DEPRECATED
#define __DEPRECATED CHROME_OLD__DEPRECATED
#undef CHROME_OLD__DEPRECATED
#endif

//- TODO: 调试的时候避免和enclave外面的BUTIL_HASH_NAMESPACE冲突
#if !defined (BUTIL_CONTAINERS_HASH_TABLES_H_)
namespace BUTIL_HASH_NAMESPACE {

// The GNU C++ library provides identity hash functions for many integral types,
// but not for |long long|.  This hash function will truncate if |size_t| is
// narrower than |long long|.  This is probably good enough for what we will
// use it for.

#define DEFINE_TRIVIAL_HASH(integral_type) \
    template<> \
    struct hash<integral_type> { \
      std::size_t operator()(integral_type value) const { \
        return static_cast<std::size_t>(value); \
      } \
    }

DEFINE_TRIVIAL_HASH(long long);
DEFINE_TRIVIAL_HASH(unsigned long long);

#undef DEFINE_TRIVIAL_HASH

// Implement string hash functions so that strings of various flavors can
// be used as keys in STL maps and sets.  The hash algorithm comes from the
// GNU C++ library, in <tr1/functional>.  It is duplicated here because GCC
// versions prior to 4.3.2 are unable to compile <tr1/functional> when RTTI
// is disabled, as it is in our build.

#define DEFINE_STRING_HASH(string_type) \
    template<> \
    struct hash<string_type> { \
      std::size_t operator()(const string_type& s) const { \
        std::size_t result = 0; \
        for (string_type::const_iterator i = s.begin(); i != s.end(); ++i) \
          result = (result * 131) + *i; \
        return result; \
      } \
    }

DEFINE_STRING_HASH(std::string);
// DEFINE_STRING_HASH(butil::string16);

#undef DEFINE_STRING_HASH

}  // namespace BUTIL_HASH_NAMESPACE
#endif


namespace sgxbutil {
using BUTIL_HASH_NAMESPACE::hash_map;
using BUTIL_HASH_NAMESPACE::hash_multimap;
using BUTIL_HASH_NAMESPACE::hash_multiset;
using BUTIL_HASH_NAMESPACE::hash_set;

// Implement hashing for pairs of at-most 32 bit integer values.
inline std::size_t HashInts32(uint32_t value1, uint32_t value2) {
  uint64_t value1_64 = value1;
  uint64_t hash64 = (value1_64 << 32) | value2;
  return static_cast<size_t>(fmix64(hash64));
}

// Implement hashing for pairs of up-to 64-bit integer values.
// We use the compound integer hash method to produce a 64-bit hash code, by
// breaking the two 64-bit inputs into 4 32-bit values:
// http://opendatastructures.org/versions/edition-0.1d/ods-java/node33.html#SECTION00832000000000000000
// Then we reduce our result to 32 bits if required, similar to above.
inline std::size_t HashInts64(uint64_t value1, uint64_t value2) {
  uint32_t short_random1 = 842304669U;
  uint32_t short_random2 = 619063811U;
  uint32_t short_random3 = 937041849U;
  uint32_t short_random4 = 3309708029U;

  uint32_t value1a = static_cast<uint32_t>(value1 & 0xffffffff);
  uint32_t value1b = static_cast<uint32_t>((value1 >> 32) & 0xffffffff);
  uint32_t value2a = static_cast<uint32_t>(value2 & 0xffffffff);
  uint32_t value2b = static_cast<uint32_t>((value2 >> 32) & 0xffffffff);

  uint64_t product1 = static_cast<uint64_t>(value1a) * short_random1;
  uint64_t product2 = static_cast<uint64_t>(value1b) * short_random2;
  uint64_t product3 = static_cast<uint64_t>(value2a) * short_random3;
  uint64_t product4 = static_cast<uint64_t>(value2b) * short_random4;

  uint64_t hash64 = product1 + product2 + product3 + product4;

  if (sizeof(std::size_t) >= sizeof(uint64_t))
    return static_cast<std::size_t>(hash64);

  uint64_t odd_random = 1578233944LL << 32 | 194370989LL;
  uint32_t shift_random = 20591U << 16;

  hash64 = hash64 * odd_random + shift_random;
  std::size_t high_bits = static_cast<std::size_t>(
      hash64 >> (8 * (sizeof(uint64_t) - sizeof(std::size_t))));
  return high_bits;
}

#define DEFINE_32BIT_PAIR_HASH(Type1, Type2) \
inline std::size_t HashPair(Type1 value1, Type2 value2) { \
  return HashInts32(value1, value2); \
}

DEFINE_32BIT_PAIR_HASH(int16_t, int16_t);
DEFINE_32BIT_PAIR_HASH(int16_t, uint16_t);
DEFINE_32BIT_PAIR_HASH(int16_t, int32_t);
DEFINE_32BIT_PAIR_HASH(int16_t, uint32_t);
DEFINE_32BIT_PAIR_HASH(uint16_t, int16_t);
DEFINE_32BIT_PAIR_HASH(uint16_t, uint16_t);
DEFINE_32BIT_PAIR_HASH(uint16_t, int32_t);
DEFINE_32BIT_PAIR_HASH(uint16_t, uint32_t);
DEFINE_32BIT_PAIR_HASH(int32_t, int16_t);
DEFINE_32BIT_PAIR_HASH(int32_t, uint16_t);
DEFINE_32BIT_PAIR_HASH(int32_t, int32_t);
DEFINE_32BIT_PAIR_HASH(int32_t, uint32_t);
DEFINE_32BIT_PAIR_HASH(uint32_t, int16_t);
DEFINE_32BIT_PAIR_HASH(uint32_t, uint16_t);
DEFINE_32BIT_PAIR_HASH(uint32_t, int32_t);
DEFINE_32BIT_PAIR_HASH(uint32_t, uint32_t);

#undef DEFINE_32BIT_PAIR_HASH

#define DEFINE_64BIT_PAIR_HASH(Type1, Type2) \
inline std::size_t HashPair(Type1 value1, Type2 value2) { \
  return HashInts64(value1, value2); \
}

DEFINE_64BIT_PAIR_HASH(int16_t, int64_t);
DEFINE_64BIT_PAIR_HASH(int16_t, uint64_t);
DEFINE_64BIT_PAIR_HASH(uint16_t, int64_t);
DEFINE_64BIT_PAIR_HASH(uint16_t, uint64_t);
DEFINE_64BIT_PAIR_HASH(int32_t, int64_t);
DEFINE_64BIT_PAIR_HASH(int32_t, uint64_t);
DEFINE_64BIT_PAIR_HASH(uint32_t, int64_t);
DEFINE_64BIT_PAIR_HASH(uint32_t, uint64_t);
DEFINE_64BIT_PAIR_HASH(int64_t, int16_t);
DEFINE_64BIT_PAIR_HASH(int64_t, uint16_t);
DEFINE_64BIT_PAIR_HASH(int64_t, int32_t);
DEFINE_64BIT_PAIR_HASH(int64_t, uint32_t);
DEFINE_64BIT_PAIR_HASH(int64_t, int64_t);
DEFINE_64BIT_PAIR_HASH(int64_t, uint64_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, int16_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, uint16_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, int32_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, uint32_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, int64_t);
DEFINE_64BIT_PAIR_HASH(uint64_t, uint64_t);

#undef DEFINE_64BIT_PAIR_HASH
}  // namespace sgxbutil

#if !defined (BUTIL_CONTAINERS_HASH_TABLES_H_)
//- TODO: 调试的时候避免和enclave外面的BUTIL_HASH_NAMESPACE冲突，所以注释掉
namespace BUTIL_HASH_NAMESPACE {

// Implement methods for hashing a pair of integers, so they can be used as
// keys in STL containers.

// NOTE(gejun): Specialize ptr as well which is supposed to work with 
// containers by default
template<typename Type1, typename Type2>
struct hash<std::pair<Type1, Type2> > {
  std::size_t operator()(std::pair<Type1, Type2> value) const {
    return sgxbutil::HashPair(value.first, value.second);
  }
};
template<typename Type>
struct hash<Type*> {
  std::size_t operator()(Type* ptr) const {
    return (uintptr_t)ptr;
  }
};

} //namespace BUTIL_HASH_NAMESPACE
#endif

#undef DEFINE_PAIR_HASH_FUNCTION_START
#undef DEFINE_PAIR_HASH_FUNCTION_END

#endif  // SGX_BUTIL_CONTAINERS_HASH_TABLES_H_
