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

// Date: Fri Sep 10 13:34:25 CST 2010

#include <errno.h>                                     // errno
#include <string.h>                                    // strerror_r
#include <stdlib.h>                                    // EXIT_FAILURE
#include <stdio.h>                                     // snprintf
#include <pthread.h>                                   // pthread_mutex_t
#include <unistd.h>                                    // _exit
#include "sgxbutil/scoped_lock.h"                         // BAIDU_SCOPED_LOCK

namespace sgxbutil {

const int ERRNO_BEGIN = -32768;
const int ERRNO_END = 32768;
static const char* errno_desc[ERRNO_END - ERRNO_BEGIN] = {};
static pthread_mutex_t modify_desc_mutex = PTHREAD_MUTEX_INITIALIZER;

const size_t ERROR_BUFSIZE = 64;
__thread char tls_error_buf[ERROR_BUFSIZE];

int DescribeCustomizedErrno(
    int error_code, const char* error_name, const char* description) {
    BAIDU_SCOPED_LOCK(modify_desc_mutex);
    if (error_code < ERRNO_BEGIN || error_code >= ERRNO_END) {
        // error() is a non-portable GNU extension that should not be used.
        fprintf(stderr, "Fail to define %s(%d) which is out of range, abort.",
              error_name, error_code);
        //- OE 并不支持 _exit，直接返回即可，事实上这个分支的代码基本不会被执行
        return -1;      
        // _exit(1);
    }
    const char* desc = errno_desc[error_code - ERRNO_BEGIN];
    if (desc) {
        if (strcmp(desc, description) == 0) {
            fprintf(stderr, "WARNING: Detected shared library loading\n");
            return -1;
        }
    } else {
        //- TODO: butil使用的是GNU版本的strerror_r，但OE似乎只支持 XSI-compliant 版本的
        //- 为简单起见，使用strerror即可满足这里的判断要求
        // desc = strerror_r(error_code, tls_error_buf, ERROR_BUFSIZE);
        desc = strerror(error_code);
        if (desc && strncmp(desc, "Unknown error", 13) != 0)
        {
            fprintf(stderr, "Fail to define %s(%d) which is already defined as `%s', abort.",
                    error_name, error_code, desc);
            //- TODO: OE 并不支持 _exit，直接返回即可，事实上这个分支的代码基本不会被执行
#ifndef RUN_OUTSIDE_SGX
            return -1;
#else
            _exit(1);
#endif
        }
    }
    errno_desc[error_code - ERRNO_BEGIN] = description;
    return 0;  // must
}

}  // namespace sgxbutil

const char* berror(int error_code) {
    if (error_code == -1) {
        return "General error -1";
    }
    if (error_code >= sgxbutil::ERRNO_BEGIN && error_code < sgxbutil::ERRNO_END) {
        const char* s = sgxbutil::errno_desc[error_code - sgxbutil::ERRNO_BEGIN];
        if (s) {
            return s;
        }
        //- TODO: butil使用的是GNU版本的strerror_r，但OE似乎只支持 XSI-compliant 版本的
        //- 为简单起见，使用strerror即可满足这里的判断要求
        s = strerror(error_code);
        // s = strerror_r(error_code, sgxbutil::tls_error_buf, sgxbutil::ERROR_BUFSIZE);
        if (s) {
            return s;
        }
    }
    snprintf(sgxbutil::tls_error_buf, sgxbutil::ERROR_BUFSIZE,
             "Unknown error %d", error_code);
    return sgxbutil::tls_error_buf;
}

const char* berror() {
    return berror(errno);
}
