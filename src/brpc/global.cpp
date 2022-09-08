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


#ifndef USE_MESALINK
#include <openssl/ssl.h>
#include <openssl/conf.h>
#else
#include <mesalink/openssl/ssl.h>
#endif

#include "google/gflags/gflags.h"
#include <fcntl.h>                               // O_RDONLY
#include <signal.h>

// Compress handlers
#include "brpc/compress.h"
// #include "brpc/policy/gzip_compress.h"
#include "brpc/policy/snappy_compress.h"

// Protocols
#include "brpc/protocol.h"
#include "brpc/policy/baidu_rpc_protocol.h"
#include "brpc/policy/http_rpc_protocol.h"
#include "brpc/policy/http2_rpc_protocol.h"

// Concurrency Limiters
#include "brpc/concurrency_limiter.h"
#include "brpc/policy/auto_concurrency_limiter.h"
#include "brpc/policy/constant_concurrency_limiter.h"

#include "brpc/input_messenger.h"     // get_or_new_client_side_messenger
#include "brpc/socket_map.h"          // SocketMapList
#include "brpc/server.h"

#include <malloc.h>                   // malloc_trim
#include "sgxbutil/fd_guard.h"
#include "sgxbutil/attestation/attestation_helper.h"

extern "C" {
// defined in gperftools/malloc_extension_c.h
void BAIDU_WEAK MallocExtension_ReleaseFreeMemory(void);
}

namespace brpc {

DEFINE_int32(free_memory_to_system_interval, 0,
             "Try to return free memory to system every so many seconds, "
             "values <= 0 disables this feature");
BRPC_VALIDATE_GFLAG(free_memory_to_system_interval, PassValidate);

namespace policy {
// Defined in http_rpc_protocol.cpp
void InitCommonStrings();
}

using namespace policy;

const char* const DUMMY_SERVER_PORT_FILE = "dummy_server.port";

struct GlobalExtensions {

    GlobalExtensions()
        : constant_cl(0) {
    }

    AutoConcurrencyLimiter auto_cl;
    ConstantConcurrencyLimiter constant_cl;
};

static pthread_once_t register_extensions_once = PTHREAD_ONCE_INIT;
static GlobalExtensions* g_ext = NULL;

static long ReadPortOfDummyServer(const char* filename) {
    sgxbutil::fd_guard fd(open(filename, O_RDONLY));
    if (fd < 0) {
        LOG(ERROR) << "Fail to open `" << DUMMY_SERVER_PORT_FILE << "'";
        return -1;
    }
    char port_str[32];
    const ssize_t nr = read(fd, port_str, sizeof(port_str));
    if (nr <= 0) {
        LOG(ERROR) << "Fail to read `" << DUMMY_SERVER_PORT_FILE << "': "
                   << (nr == 0 ? "nothing to read" : berror());
        return -1;
    }
    port_str[std::min((size_t)nr, sizeof(port_str)-1)] = '\0';
    const char* p = port_str;
    for (; isspace(*p); ++p) {}
    char* endptr = NULL;
    const long port = strtol(p, &endptr, 10);
    for (; isspace(*endptr); ++endptr) {}
    if (*endptr != '\0') {
        LOG(ERROR) << "Invalid port=`" << port_str << "'";
        return -1;
    }
    return port;
}

// Expose counters of sgxbutil::IOBuf
static int64_t GetIOBufBlockCount(void*) {
    return sgxbutil::IOBuf::block_count();
}
static int64_t GetIOBufBlockCountHitTLSThreshold(void*) {
    return sgxbutil::IOBuf::block_count_hit_tls_threshold();
}
static int64_t GetIOBufNewBigViewCount(void*) {
    return sgxbutil::IOBuf::new_bigview_count();
}
static int64_t GetIOBufBlockMemory(void*) {
    return sgxbutil::IOBuf::block_memory();
}

// Defined in server.cpp
extern sgxbutil::static_atomic<int> g_running_server_count;
static int GetRunningServerCount(void*) {
    return g_running_server_count.load(sgxbutil::memory_order_relaxed);
}

// Update global stuff periodically.
static void* GlobalUpdate(void*) {
    // Expose variables.
    // bvar::PassiveStatus<int64_t> var_iobuf_block_count(
    //     "iobuf_block_count", GetIOBufBlockCount, NULL);
    // bvar::PassiveStatus<int64_t> var_iobuf_block_count_hit_tls_threshold(
    //     "iobuf_block_count_hit_tls_threshold",
        // GetIOBufBlockCountHitTLSThreshold, NULL);
    // bvar::PassiveStatus<int64_t> var_iobuf_new_bigview_count(
    //     GetIOBufNewBigViewCount, NULL);
    // bvar::PerSecond<bvar::PassiveStatus<int64_t> > var_iobuf_new_bigview_second(
    //     "iobuf_newbigview_second", &var_iobuf_new_bigview_count);
    // bvar::PassiveStatus<int64_t> var_iobuf_block_memory(
    //     "iobuf_block_memory", GetIOBufBlockMemory, NULL);
    // bvar::PassiveStatus<int> var_running_server_count(
    //     "rpc_server_count", GetRunningServerCount, NULL);

    //- Don't need dummy server in sgx-braft
    // butil::FileWatcher fw;
    // if (fw.init_from_not_exist(DUMMY_SERVER_PORT_FILE) < 0) {
    //     LOG(FATAL) << "Fail to init FileWatcher on `" << DUMMY_SERVER_PORT_FILE << "'";
    //     return NULL;
    // }

    std::vector<SocketId> conns;
    const int64_t start_time_us = sgxbutil::gettimeofday_us();
    const int WARN_NOSLEEP_THRESHOLD = 2;
    int64_t last_time_us = start_time_us;
    int consecutive_nosleep = 0;
    int64_t last_return_free_memory_time = start_time_us;
    while (1) {
        // LOG(INFO) << __FUNCTION__;
        const int64_t sleep_us = 1000000L + last_time_us - sgxbutil::gettimeofday_us();
        if (sleep_us > 0) {
            if (bthread_usleep(sleep_us) < 0) {
                PLOG_IF(FATAL, errno != ESTOP) << "Fail to sleep";
                break;
            }
            consecutive_nosleep = 0;
        } else {
            if (++consecutive_nosleep >= WARN_NOSLEEP_THRESHOLD) {
                consecutive_nosleep = 0;
                LOG(WARNING) << __FUNCTION__ << " is too busy!";
            }
        }
        last_time_us = sgxbutil::gettimeofday_us();

        //- Don't need dummy server in sgx-braft
        // if (!IsDummyServerRunning()
        //     && g_running_server_count.load(sgxbutil::memory_order_relaxed) == 0
        //     && fw.check_and_consume() > 0) {
        //     long port = ReadPortOfDummyServer(DUMMY_SERVER_PORT_FILE);
        //     if (port >= 0) {
        //         StartDummyServerAt(port);
        //     }
        // }

        SocketMapList(&conns);
        const int64_t now_ms = sgxbutil::cpuwide_time_ms();
        for (size_t i = 0; i < conns.size(); ++i) {
            SocketUniquePtr ptr;
            if (Socket::Address(conns[i], &ptr) == 0) {
                ptr->UpdateStatsEverySecond(now_ms);
            }
        }

        const int return_mem_interval =
            FLAGS_free_memory_to_system_interval/*reloadable*/;
        if (return_mem_interval > 0 &&
            last_time_us >= last_return_free_memory_time +
            return_mem_interval * 1000000L) {
            last_return_free_memory_time = last_time_us;
            // TODO: Calling MallocExtension::instance()->ReleaseFreeMemory may
            // crash the program in later calls to malloc, verified on tcmalloc
            // 1.7 and 2.5, which means making the static member function weak
            // in details/tcmalloc_extension.cpp is probably not correct, however
            // it does work for heap profilers.
            if (MallocExtension_ReleaseFreeMemory != NULL) {
                MallocExtension_ReleaseFreeMemory();
            } else {
                // GNU specific.
                //- OE don't support malloc_trim, TODO: Does this impact the performance?
#if RUN_OUTSIDE_SGX && USE_NORMAL_FUNCTION
                malloc_trim(10 * 1024 * 1024/*leave 10M pad*/);
#endif                
            }
        }
    } //- while(1)
    return NULL;
}

static void BaiduStreamingLogHandler(google::protobuf::LogLevel level,
                                     const char* filename, int line,
                                     const std::string& message) {
    switch (level) {
    case google::protobuf::LOGLEVEL_INFO:
        LOG(INFO) << filename << ':' << line << ' ' << message;
        return;
    case google::protobuf::LOGLEVEL_WARNING:
        LOG(WARNING) << filename << ':' << line << ' ' << message;
        return;
    case google::protobuf::LOGLEVEL_ERROR:
        LOG(ERROR) << filename << ':' << line << ' ' << message;
        return;
    case google::protobuf::LOGLEVEL_FATAL:
        LOG(FATAL) << filename << ':' << line << ' ' << message;
        return;
    }
    CHECK(false) << filename << ':' << line << ' ' << message;
}

static void GlobalInitializeOrDieImpl() {
    //////////////////////////////////////////////////////////////////
    // Be careful about usages of gflags inside this function which //
    // may be called before main() only seeing gflags with default  //
    // values even if the gflags will be set after main().          //
    //////////////////////////////////////////////////////////////////

    // Ignore SIGPIPE.
    struct sigaction oldact;
    if (sigaction(SIGPIPE, NULL, &oldact) != 0 ||
            (oldact.sa_handler == NULL && oldact.sa_sigaction == NULL)) {
        CHECK(NULL == signal(SIGPIPE, SIG_IGN));
    }

    // Make GOOGLE_LOG print to comlog device
    SetLogHandler(&BaiduStreamingLogHandler);

    // Setting the variable here does not work, the profiler probably check
    // the variable before main() for only once.
    // setenv("TCMALLOC_SAMPLE_PARAMETER", "524288", 0);

    // Initialize openssl library
    SSL_library_init();
    // RPC doesn't require openssl.cnf, users can load it by themselves if needed
    SSL_load_error_strings();
    if (SSLThreadInit() != 0 || SSLDHInit() != 0) {
        exit(1);
    }

#ifdef SGX_USE_REMOTE_ATTESTATION
    //- After the initialization of SSL lib, we can derive raft node's cert/pkey
    if (get_global_cert_and_pkey() != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " get_global_cert_and_pkey faliled";
        exit(1);
    }
#endif

    // Defined in http_rpc_protocol.cpp
    InitCommonStrings();

    // Leave memory of these extensions to process's clean up.
    g_ext = new(std::nothrow) GlobalExtensions();
    if (NULL == g_ext) {
        exit(1);
    }

    // Compress Handlers

    //- Remove GZIP support
    // const CompressHandler gzip_compress =
    //     { GzipCompress, GzipDecompress, "gzip" };
    // if (RegisterCompressHandler(COMPRESS_TYPE_GZIP, gzip_compress) != 0) {
    //     exit(1);
    // }
    // const CompressHandler zlib_compress =
    //     { ZlibCompress, ZlibDecompress, "zlib" };
    // if (RegisterCompressHandler(COMPRESS_TYPE_ZLIB, zlib_compress) != 0) {
    //     exit(1);
    // }

    // - Don't use snappy for porting simplification
    const CompressHandler snappy_compress =
        { SnappyCompress, SnappyDecompress, "snappy" };
    if (RegisterCompressHandler(COMPRESS_TYPE_SNAPPY, snappy_compress) != 0) {
        exit(1);
    }

    // Protocols
    //- Only keep baidu_std and http, and remove others
    Protocol baidu_protocol = { ParseRpcMessage,
                                SerializeRequestDefault, PackRpcRequest,
                                ProcessRpcRequest, ProcessRpcResponse,
                                VerifyRpcRequest, NULL, NULL,
                                CONNECTION_TYPE_ALL, "baidu_std" };
    if (RegisterProtocol(PROTOCOL_BAIDU_STD, baidu_protocol) != 0) {
        exit(1);
    }

    Protocol http_protocol = { ParseHttpMessage,
                               SerializeHttpRequest, PackHttpRequest,
                               ProcessHttpRequest, ProcessHttpResponse,
                               VerifyHttpRequest, ParseHttpServerAddress,
                               GetHttpMethodName,
                               CONNECTION_TYPE_POOLED_AND_SHORT,
                               "http" };
    if (RegisterProtocol(PROTOCOL_HTTP, http_protocol) != 0) {
        exit(1);
    }

    Protocol http2_protocol = { ParseH2Message,
                                SerializeHttpRequest, PackH2Request,
                                ProcessHttpRequest, ProcessHttpResponse,
                                VerifyHttpRequest, ParseHttpServerAddress,
                                GetHttpMethodName,
                                CONNECTION_TYPE_SINGLE,
                                "h2" };
    if (RegisterProtocol(PROTOCOL_H2, http2_protocol) != 0) {
        exit(1);
    }

    std::vector<Protocol> protocols;
    ListProtocols(&protocols);
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (protocols[i].process_response) {
            InputMessageHandler handler;
            // `process_response' is required at client side
            handler.parse = protocols[i].parse;
            handler.process = protocols[i].process_response;
            // No need to verify at client side
            handler.verify = NULL;
            handler.arg = NULL;
            handler.name = protocols[i].name;
            if (get_or_new_client_side_messenger()->AddHandler(handler) != 0) {
                exit(1);
            }
        }
    }

    // Concurrency Limiters
    ConcurrencyLimiterExtension()->RegisterOrDie("auto", &g_ext->auto_cl);
    ConcurrencyLimiterExtension()->RegisterOrDie("constant", &g_ext->constant_cl);

    // We never join GlobalUpdate, let it quit with the process.
    bthread_t th;
    CHECK(bthread_start_background(&th, NULL, GlobalUpdate, NULL) == 0)
        << "Fail to start GlobalUpdate";
}

void GlobalInitializeOrDie() {
    if (pthread_once(&register_extensions_once,
                     GlobalInitializeOrDieImpl) != 0) {
        LOG(FATAL) << "Fail to pthread_once";
        exit(1);
    }
}

} // namespace brpc
