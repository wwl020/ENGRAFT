// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//- See https://gcc.gnu.org/wiki/Visibility
#ifndef SGX_BUTIL_BASE_EXPORT_H_
#define SGX_BUTIL_BASE_EXPORT_H_

#if defined(COMPONENT_BUILD)

#if defined(BUTIL_IMPLEMENTATION)
#define BUTIL_EXPORT __attribute__((visibility("default")))
#define BUTIL_EXPORT_PRIVATE __attribute__((visibility("default")))
#else
#define BUTIL_EXPORT
#define BUTIL_EXPORT_PRIVATE
#endif  // defined(BUTIL_IMPLEMENTATION)


#else  // defined(COMPONENT_BUILD)
#define BUTIL_EXPORT
#define BUTIL_EXPORT_PRIVATE
#endif

#endif  // SGX_BUTIL_BASE_EXPORT_H_
