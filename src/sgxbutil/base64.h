// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SGXBUTIL_BASE64_H__
#define SGXBUTIL_BASE64_H__

#include <string>

#include "sgxbutil/base_export.h"
#include "sgxbutil/strings/string_piece.h"

namespace sgxbutil {

// Encodes the input string in base64.
BUTIL_EXPORT void Base64Encode(const StringPiece& input, std::string* output);

// Decodes the base64 input string.  Returns true if successful and false
// otherwise.  The output string is only modified if successful.
BUTIL_EXPORT bool Base64Decode(const StringPiece& input, std::string* output);

}  // namespace sgxbutil

#endif  // SGXBUTIL_BASE64_H__
