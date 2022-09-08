// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SGX_BUTIL_FILES_DIR_READER_POSIX_H_
#define SGX_BUTIL_FILES_DIR_READER_POSIX_H_

// #include "butil/build_config.h"

// This header provides a class, DirReaderPosix, which allows one to open and
// read from directories without allocating memory. For the interface, see
// the generic fallback in dir_reader_fallback.h.

// Mac note: OS X has getdirentries, but it only works if we restrict Chrome to
// 32-bit inodes. There is a getdirentries64 syscall in 10.6, but it's not
// wrapped and the direct syscall interface is unstable. Using an unstable API
// seems worse than falling back to enumerating all file descriptors so we will
// probably never implement this on the Mac.

#include "sgxbutil/files/dir_reader_linux.h"

namespace sgxbutil {

typedef DirReaderLinux DirReaderPosix;


}  // namespace sgxbutil

#endif // SGX_BUTIL_FILES_DIR_READER_POSIX_H_
