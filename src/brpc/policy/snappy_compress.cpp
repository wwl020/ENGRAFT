// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.


#include "sgxbutil/logging.h"
#include "sgxbutil/third_party/snappy/snappy.h"
#include "brpc/policy/snappy_compress.h"
#include "brpc/protocol.h"


namespace brpc {
namespace policy {

bool SnappyCompress(const google::protobuf::Message& res, sgxbutil::IOBuf* buf) {
    sgxbutil::IOBuf serialized_pb;
    sgxbutil::IOBufAsZeroCopyOutputStream wrapper(&serialized_pb);
    if (res.SerializeToZeroCopyStream(&wrapper)) {
        sgxbutil::IOBufAsSnappySource source(serialized_pb);
        sgxbutil::IOBufAsSnappySink sink(*buf);
        return sgxbutil::snappy::Compress(&source, &sink);
    }
    LOG(WARNING) << "Fail to serialize input pb=" << &res;
    return false;
}

bool SnappyDecompress(const sgxbutil::IOBuf& data, google::protobuf::Message* req) {
    sgxbutil::IOBufAsSnappySource source(data);
    sgxbutil::IOBuf binary_pb;
    sgxbutil::IOBufAsSnappySink sink(binary_pb);
    if (sgxbutil::snappy::Uncompress(&source, &sink)) {
        return ParsePbFromIOBuf(req, binary_pb);
    }
    LOG(WARNING) << "Fail to snappy::Uncompress, size=" << data.size();
    return false;
}

bool SnappyCompress(const sgxbutil::IOBuf& in, sgxbutil::IOBuf* out) {
    sgxbutil::IOBufAsSnappySource source(in);
    sgxbutil::IOBufAsSnappySink sink(*out);
    return sgxbutil::snappy::Compress(&source, &sink);
}

bool SnappyDecompress(const sgxbutil::IOBuf& in, sgxbutil::IOBuf* out) {
    sgxbutil::IOBufAsSnappySource source(in);
    sgxbutil::IOBufAsSnappySink sink(*out);
    return sgxbutil::snappy::Uncompress(&source, &sink);
}

}  // namespace policy
} // namespace brpc
