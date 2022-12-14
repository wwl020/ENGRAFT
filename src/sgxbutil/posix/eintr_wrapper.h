// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This provides a wrapper around system calls which may be interrupted by a
// signal and return EINTR. See man 7 signal.
// To prevent long-lasting loops (which would likely be a bug, such as a signal
// that should be masked) to go unnoticed, there is a limit after which the
// caller will nonetheless see an EINTR in Debug builds.
//
// On Windows, this wrapper macro does nothing.
//
// Don't wrap close calls in HANDLE_EINTR. Use IGNORE_EINTR if the return
// value of close is significant. See http://crbug.com/269623.

//- EINTR errno means that a system call is interrupted by a signal, so our HANDLE_EINTR function 
//- will continuously issue the system call until it is finished (See the while loop)
//- More info: https://stackoverflow.com/questions/41474299/checking-if-errno-eintr-what-does-it-mean

#ifndef SGX_BUTIL_POSIX_EINTR_WRAPPER_H_
#define SGX_BUTIL_POSIX_EINTR_WRAPPER_H_

// #include "butil/build_config.h"
#include "sgxbutil/macros.h"   // BAIDU_TYPEOF


#include <errno.h>

#if defined(NDEBUG)

#define HANDLE_EINTR(x) ({ \
  BAIDU_TYPEOF(x) eintr_wrapper_result; \
  do { \
    eintr_wrapper_result = (x); \
  } while (eintr_wrapper_result == -1 && errno == EINTR); \
  eintr_wrapper_result; \
})

#else

#define HANDLE_EINTR(x) ({ \
  int eintr_wrapper_counter = 0; \
  BAIDU_TYPEOF(x) eintr_wrapper_result; \
  do { \
    eintr_wrapper_result = (x); \
  } while (eintr_wrapper_result == -1 && errno == EINTR && \
           eintr_wrapper_counter++ < 100); \
  eintr_wrapper_result; \
})

#endif  // NDEBUG

#define IGNORE_EINTR(x) ({ \
  BAIDU_TYPEOF(x) eintr_wrapper_result;     \
  do { \
    eintr_wrapper_result = (x); \
    if (eintr_wrapper_result == -1 && errno == EINTR) { \
      eintr_wrapper_result = 0; \
    } \
  } while (0); \
  eintr_wrapper_result; \
})


#endif  // SGX_BUTIL_POSIX_EINTR_WRAPPER_H_
