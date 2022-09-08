// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SGX_BUTIL_COMPILER_SPECIFIC_H_
#define SGX_BUTIL_COMPILER_SPECIFIC_H_
//- Suppose we use COMPILER_GCC(__GNUC__), ARCH_CPU_X86_64, BUTIL_CXX11_ENABLED,
//- OS_LINUX, OS_POSIX in build_config, so we don't 
//- include it. (Specific GCC version is required in some situations, see the comment.)
// #include "butil/build_config.h"

//- TODO: Following 7 lines can be removed if we don't use MSVC things in braft
#define MSVC_SUPPRESS_WARNING(n)
#define MSVC_PUSH_DISABLE_WARNING(n)
#define MSVC_PUSH_WARNING_LEVEL(n)
#define MSVC_POP_WARNING()
#define MSVC_DISABLE_OPTIMIZE()
#define MSVC_ENABLE_OPTIMIZE()
#define NON_EXPORTED_BASE(code) code



// The C++ standard requires that static const members have an out-of-class
// definition (in a single compilation unit), but MSVC chokes on this (when
// language extensions, which are required, are enabled). (You're only likely to
// notice the need for a definition if you take the address of the member or,
// more commonly, pass it to a function that takes it as a reference argument --
// probably an STL function.) This macro makes MSVC do the right thing. See
// http://msdn.microsoft.com/en-us/library/34h23df8(v=vs.100).aspx for more
// information. Use like:
//
// In .h file:
//   struct Foo {
//     static const int kBar = 5;
//   };
//
// In .cc file:
//   STATIC_CONST_MEMBER_DEFINITION const int Foo::kBar;

#define STATIC_CONST_MEMBER_DEFINITION

// Annotate a variable indicating it's ok if the variable is not used.
// (Typically used to silence a compiler warning when the assignment
// is important for some other reason.)
// Use like:
//   int x ALLOW_UNUSED = ...;
#define ALLOW_UNUSED __attribute__((unused))


// Annotate a function indicating it should not be inlined.
// Use like:
//   NOINLINE void DoStuff() { ... }
#define NOINLINE __attribute__((noinline))

#ifndef BUTIL_FORCE_INLINE
#define BUTIL_FORCE_INLINE inline __attribute__((always_inline))
#endif  // BUTIL_FORCE_INLINE

// Specify memory alignment for structs, classes, etc.
// Use like:
//   class ALIGNAS(16) MyClass { ... }
//   ALIGNAS(16) int array[4];
#define ALIGNAS(byte_alignment) __attribute__((aligned(byte_alignment)))

// Return the byte alignment of the given type (available at compile time).  Use
// sizeof(type) prior to checking __alignof to workaround Visual C++ bug:
// http://goo.gl/isH0C
// Use like:
//   ALIGNOF(int32_t)  // this would be 4
#define ALIGNOF(type) __alignof__(type)

// Annotate a virtual method indicating it must be overriding a virtual
// method in the parent class.
// Use like:
//   virtual void foo() OVERRIDE;
//- Clang or GCC_version >= 4.7
#define OVERRIDE override


// Annotate a virtual method indicating that subclasses must not override it,
// or annotate a class to indicate that it cannot be subclassed.
// Use like:
//   virtual void foo() FINAL;
//   class B FINAL : public A {};
//- Clang or GCC_version >= 4.7
#define FINAL final


// Annotate a function indicating the caller must examine the return value.
// Use like:
//   int foo() WARN_UNUSED_RESULT;
// To explicitly ignore a result, see |ignore_result()| in "butil/basictypes.h".
//- In Clang8, __GNUC__ = 4, __GNUC_MINOR__ = 2
//- So we simply set WARN_UNUSED_RESULT empty.
// #if defined(COMPILER_GCC) && __cplusplus >= 201103 && \
//       (__GNUC__ * 10000 + __GNUC_MINOR__ * 100) >= 40700
// #define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
// #else
#define WARN_UNUSED_RESULT
// #endif

// Tell the compiler a function is using a printf-style format string.
// |format_param| is the one-based index of the format string parameter;
// |dots_param| is the one-based index of the "..." parameter.
// For v*printf functions (which take a va_list), pass 0 for dots_param.
// (This is undocumented but matches what the system C headers do.)
#define PRINTF_FORMAT(format_param, dots_param) \
    __attribute__((format(printf, format_param, dots_param)))


// WPRINTF_FORMAT is the same, but for wide format strings.
// This doesn't appear to yet be implemented in any compiler.
// See http://gcc.gnu.org/bugzilla/show_bug.cgi?id=38308 .
#define WPRINTF_FORMAT(format_param, dots_param)
// If available, it would look like:
//   __attribute__((format(wprintf, format_param, dots_param)))

// MemorySanitizer annotations.
//- TODO: MEMORY_SANITIZER这一部分暂时用不到
// #if defined(MEMORY_SANITIZER) && !defined(OS_NACL)
// #include <sanitizer/msan_interface.h>

// // Mark a memory region fully initialized.
// // Use this to annotate code that deliberately reads uninitialized data, for
// // example a GC scavenging root set pointers from the stack.
// #define MSAN_UNPOISON(p, s)  __msan_unpoison(p, s)
// #else  // MEMORY_SANITIZER
// #define MSAN_UNPOISON(p, s)
// #endif  // MEMORY_SANITIZER

// Macro useful for writing cross-platform function pointers.
#if !defined(CDECL)
#define CDECL
#endif  // !defined(CDECL)

// Mark a branch likely or unlikely to be true.
// We can't remove the BAIDU_ prefix because the name is likely to conflict,
// namely kylin already has the macro.
#define BAIDU_LIKELY(expr) (__builtin_expect((bool)(expr), true))
#define BAIDU_UNLIKELY(expr) (__builtin_expect((bool)(expr), false))



// BAIDU_DEPRECATED void dont_call_me_anymore(int arg);
// ...
// warning: 'void dont_call_me_anymore(int)' is deprecated
#define BAIDU_DEPRECATED __attribute__((deprecated))

// Mark function as weak. This is GCC only feature.
//- TODO: This feature may not be used inside enclave, and can it be removed?
# define BAIDU_WEAK __attribute__((weak))

// Cacheline related --------------------------------------
#define BAIDU_CACHELINE_SIZE 64

// #ifdef __GNUC__
# define BAIDU_CACHELINE_ALIGNMENT __attribute__((aligned(BAIDU_CACHELINE_SIZE)))
// #endif /* __GNUC__ */


#ifndef BAIDU_NOEXCEPT
#define BAIDU_NOEXCEPT noexcept
#endif

#endif  // SGX_BUTIL_COMPILER_SPECIFIC_H_
