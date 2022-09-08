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


#include <inttypes.h>
#include "google/protobuf/descriptor.h"
#include "google/gflags/gflags.h"
#include "sgxbutil/time.h"                              // milliseconds_from_now
#include "sgxbutil/logging.h"
#include "sgxbutil/third_party/murmurhash3/murmurhash3.h"
#include "sgxbutil/strings/string_util.h"
#include "brpc/socket_map.h"                         // SocketMapInsert
#include "brpc/compress.h"
#include "brpc/global.h"
#include "brpc/controller.h"
#include "brpc/channel.h"
#include "bthread/unstable.h"                        // bthread_timer_add

namespace brpc {

ChannelOptions::ChannelOptions()
    : connect_timeout_ms(200)
    , timeout_ms(500)
    , max_retry(3)
    , protocol(PROTOCOL_BAIDU_STD)
    , connection_type(CONNECTION_TYPE_UNKNOWN)
    , succeed_without_server(true)
    , log_succeed_without_server(true)
    , auth(NULL)
{}

ChannelSSLOptions* ChannelOptions::mutable_ssl_options() {
    if (!_ssl_options) {
        _ssl_options.reset(new ChannelSSLOptions);
    }
    return _ssl_options.get();
}

static ChannelSignature ComputeChannelSignature(const ChannelOptions& opt) {
    if (opt.auth == NULL &&
        !opt.has_ssl_options() &&
        opt.connection_group.empty()) {
        // Returning zeroized result by default is more intuitive for users.
        return ChannelSignature();
    }
    uint32_t seed = 0;
    std::string buf;
    buf.reserve(1024);
    sgxbutil::MurmurHash3_x64_128_Context mm_ctx;
    do {
        buf.clear();
        sgxbutil::MurmurHash3_x64_128_Init(&mm_ctx, seed);

        if (!opt.connection_group.empty()) {
            buf.append("|conng=");
            buf.append(opt.connection_group);
        }
        if (opt.auth) {
            buf.append("|auth=");
            buf.append((char*)&opt.auth, sizeof(opt.auth));
        }
        if (opt.has_ssl_options()) {
            const ChannelSSLOptions& ssl = opt.ssl_options();
            buf.push_back('|');
            buf.append(ssl.ciphers);
            buf.push_back('|');
            buf.append(ssl.protocols);
            buf.push_back('|');
            buf.append(ssl.sni_name);
            const VerifyOptions& verify = ssl.verify;
            buf.push_back('|');
            buf.append((char*)&verify.verify_depth, sizeof(verify.verify_depth));
            buf.push_back('|');
            buf.append(verify.ca_file_path);
        } else {
            // All disabled ChannelSSLOptions are the same
        }
        sgxbutil::MurmurHash3_x64_128_Update(&mm_ctx, buf.data(), buf.size());
        buf.clear();
    
        if (opt.has_ssl_options()) {
            const CertInfo& cert = opt.ssl_options().client_cert;
            if (!cert.certificate.empty()) {
                // Certificate may be too long (PEM string) to fit into `buf'
                sgxbutil::MurmurHash3_x64_128_Update(
                    &mm_ctx, cert.certificate.data(), cert.certificate.size());
                sgxbutil::MurmurHash3_x64_128_Update(
                    &mm_ctx, cert.private_key.data(), cert.private_key.size());
            }
        }
        // sni_filters has no effect in ChannelSSLOptions
        ChannelSignature result;
        sgxbutil::MurmurHash3_x64_128_Final(result.data, &mm_ctx);
        if (result != ChannelSignature()) {
            // the empty result is reserved for default case and cannot
            // be used, increment the seed and retry.
            return result;
        }
        ++seed;
    } while (true);
}

Channel::Channel(ProfilerLinker)
    : _server_id(INVALID_SOCKET_ID)
    , _serialize_request(NULL)
    , _pack_request(NULL)
    , _get_method_name(NULL)
    , _preferred_index(-1) {
}

Channel::~Channel() {
    if (_server_id != INVALID_SOCKET_ID) {
        const ChannelSignature sig = ComputeChannelSignature(_options);
        SocketMapRemove(SocketMapKey(_server_address, sig));
    }
}

int Channel::InitChannelOptions(const ChannelOptions* options) {
    if (options) {  // Override default options if user provided one.
        _options = *options;
    }
    const Protocol* protocol = FindProtocol(_options.protocol);
    if (NULL == protocol || !protocol->support_client()) {
        LOG(ERROR) << "Channel does not support the protocol";
        return -1;
    }
    _serialize_request = protocol->serialize_request;
    _pack_request = protocol->pack_request;
    _get_method_name = protocol->get_method_name;

    // Check connection_type
    if (_options.connection_type == CONNECTION_TYPE_UNKNOWN) {
        // Save has_error which will be overriden in later assignments to
        // connection_type.
        const bool has_error = _options.connection_type.has_error();
        
        if (protocol->supported_connection_type & CONNECTION_TYPE_SINGLE) {
            _options.connection_type = CONNECTION_TYPE_SINGLE;
        } else if (protocol->supported_connection_type & CONNECTION_TYPE_POOLED) {
            _options.connection_type = CONNECTION_TYPE_POOLED;
        } else {
            _options.connection_type = CONNECTION_TYPE_SHORT;
        }
        if (has_error) {
            LOG(ERROR) << "Channel=" << this << " chose connection_type="
                       << _options.connection_type.name() << " for protocol="
                       << _options.protocol.name();
        }
    } else {
        if (!(_options.connection_type & protocol->supported_connection_type)) {
            LOG(ERROR) << protocol->name << " does not support connection_type="
                       << ConnectionTypeToString(_options.connection_type);
            return -1;
        }
    }

    _preferred_index = get_client_side_messenger()->FindProtocolIndex(_options.protocol);
    if (_preferred_index < 0) {
        LOG(ERROR) << "Fail to get index for protocol="
                   << _options.protocol.name();
        return -1;
    }

    // Normalize connection_group
    std::string& cg = _options.connection_group;
    if (!cg.empty() && (::isspace(cg.front()) || ::isspace(cg.back()))) {
        sgxbutil::TrimWhitespace(cg, sgxbutil::TRIM_ALL, &cg);
    }
    return 0;
}

int Channel::Init(const char* server_addr_and_port,
                  const ChannelOptions* options) {
    GlobalInitializeOrDie();
    sgxbutil::EndPoint point;
    const AdaptiveProtocolType& ptype = (options ? options->protocol : _options.protocol);
    const Protocol* protocol = FindProtocol(ptype);
    if (protocol == NULL || !protocol->support_client()) {
        LOG(ERROR) << "Channel does not support the protocol";
        return -1;
    }
    if (protocol->parse_server_address != NULL) {
        if (!protocol->parse_server_address(&point, server_addr_and_port)) {
            LOG(ERROR) << "Fail to parse address=`" << server_addr_and_port << '\'';
            return -1;
        }
    } else {
        if (str2endpoint(server_addr_and_port, &point) != 0 &&
            hostname2endpoint(server_addr_and_port, &point) != 0) {
            // Many users called the wrong Init(). Print some log to save
            // our troubleshooting time.
            if (strstr(server_addr_and_port, "://")) {
                LOG(ERROR) << "Invalid address=`" << server_addr_and_port
                           << "'. Use Init(naming_service_name, "
                    "load_balancer_name, options) instead.";
            } else {
                LOG(ERROR) << "Invalid address=`" << server_addr_and_port << '\'';
            }
            return -1;
        }
    }
    return InitSingle(point, server_addr_and_port, options);
}

int Channel::Init(const char* server_addr, int port,
                  const ChannelOptions* options) {
    GlobalInitializeOrDie();
    sgxbutil::EndPoint point;
    const AdaptiveProtocolType& ptype = (options ? options->protocol : _options.protocol);
    const Protocol* protocol = FindProtocol(ptype);
    if (protocol == NULL || !protocol->support_client()) {
        LOG(ERROR) << "Channel does not support the protocol";
        return -1;
    }
    if (protocol->parse_server_address != NULL) {
        if (!protocol->parse_server_address(&point, server_addr)) {
            LOG(ERROR) << "Fail to parse address=`" << server_addr << '\'';
            return -1;
        }
        point.port = port;
    } else {
        if (str2endpoint(server_addr, port, &point) != 0 &&
            hostname2endpoint(server_addr, port, &point) != 0) {
            LOG(ERROR) << "Invalid address=`" << server_addr << '\'';
            return -1;
        }
    }
    return InitSingle(point, server_addr, options);
}

static int CreateSocketSSLContext(const ChannelOptions& options,
                                  std::shared_ptr<SocketSSLContext>* ssl_ctx) {
    if (options.has_ssl_options()) {
        SSL_CTX* raw_ctx = CreateClientSSLContext(options.ssl_options());
        if (!raw_ctx) {
            LOG(ERROR) << "Fail to CreateClientSSLContext";
            return -1;
        }
        *ssl_ctx = std::make_shared<SocketSSLContext>();
        (*ssl_ctx)->raw_ctx = raw_ctx;
        (*ssl_ctx)->sni_name = options.ssl_options().sni_name;
    } else {
        (*ssl_ctx) = NULL;
    }
    return 0;
}

int Channel::Init(sgxbutil::EndPoint server_addr_and_port,
                  const ChannelOptions* options) {
    return InitSingle(server_addr_and_port, "", options);
}

int Channel::InitSingle(const sgxbutil::EndPoint& server_addr_and_port,
                        const char* raw_server_address,
                        const ChannelOptions* options) {
    GlobalInitializeOrDie();
    if (InitChannelOptions(options) != 0) {
        return -1;
    }
    if (_options.protocol == brpc::PROTOCOL_HTTP &&
        ::strncmp(raw_server_address, "https://", 8) == 0) {
        if (_options.mutable_ssl_options()->sni_name.empty()) {
            ParseURL(raw_server_address,
                     NULL, &_options.mutable_ssl_options()->sni_name, NULL);
        }
    }
    const int port = server_addr_and_port.port;
    if (port < 0 || port > 65535) {
        LOG(ERROR) << "Invalid port=" << port;
        return -1;
    }
    _server_address = server_addr_and_port;
    const ChannelSignature sig = ComputeChannelSignature(_options);
    std::shared_ptr<SocketSSLContext> ssl_ctx;
    if (CreateSocketSSLContext(_options, &ssl_ctx) != 0) {
        return -1;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " Before insertion, _server_id = " << _server_id;
    if (SocketMapInsert(SocketMapKey(server_addr_and_port, sig),
                        &_server_id, ssl_ctx) != 0) {
        LOG(ERROR) << "Fail to insert into SocketMap";
        return -1;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " After insertion, _server_id = " << _server_id;
    return 0;
}

static void HandleTimeout(void* arg) {
    bthread_id_t correlation_id = { (uint64_t)arg };
    bthread_id_error(correlation_id, ERPCTIMEDOUT);
}


void Channel::CallMethod(const google::protobuf::MethodDescriptor* method,
                         google::protobuf::RpcController* controller_base,
                         const google::protobuf::Message* request,
                         google::protobuf::Message* response,
                         google::protobuf::Closure* done) {
    const int64_t start_send_real_us = sgxbutil::gettimeofday_us();
    Controller* cntl = static_cast<Controller*>(controller_base);
    cntl->OnRPCBegin(start_send_real_us);

    // Override max_retry first to reset the range of correlation_id
    if (cntl->max_retry() == UNSET_MAGIC_NUM) {
        cntl->set_max_retry(_options.max_retry);
    }
    if (cntl->max_retry() < 0) {
        // this is important because #max_retry decides #versions allocated
        // in correlation_id. negative max_retry causes undefined behavior.
        cntl->set_max_retry(0);
    }
    // HTTP needs this field to be set before any SetFailed()
    cntl->_request_protocol = _options.protocol;
    if (_options.protocol.has_param()) {
        CHECK(cntl->protocol_param().empty());
        cntl->protocol_param() = _options.protocol.param();
    }
    cntl->_preferred_index = _preferred_index;
    const CallId correlation_id = cntl->call_id();
    LOG(INFO) << "Func: " << __FUNCTION__ << " pthread-" << pthread_self() << " Call ID = " << cntl->_correlation_id;
    const int rc = bthread_id_lock_and_reset_range(
                    correlation_id, NULL, 2 + cntl->max_retry());

    if (rc != 0) {
        CHECK_EQ(EINVAL, rc);
        if (!cntl->FailedInline()) {
            cntl->SetFailed(EINVAL, "Fail to lock call_id=%" PRId64,
                            correlation_id.value);
        }
        LOG_IF(ERROR, cntl->is_used_by_rpc())
            << "Controller=" << cntl << " was used by another RPC before. "
            "Did you forget to Reset() it before reuse?";
        // Have to run done in-place. If the done runs in another thread,
        // Join() on this RPC is no-op and probably ends earlier than running
        // the callback and releases resources used in the callback.
        // Since this branch is only entered by wrongly-used RPC, the
        // potentially introduced deadlock(caused by locking RPC and done with
        // the same non-recursive lock) is acceptable and removable by fixing
        // user's code.
        if (done) {
            done->Run();
        }
        return;
    }

    cntl->set_used_by_rpc();

    // Override some options if they haven't been set by Controller
    if (cntl->timeout_ms() == UNSET_MAGIC_NUM) {
        cntl->set_timeout_ms(_options.timeout_ms);
    }
    // Since connection is shared extensively amongst channels and RPC,
    // overriding connect_timeout_ms does not make sense, just use the
    // one in ChannelOptions
    cntl->_connect_timeout_ms = _options.connect_timeout_ms;
    if (cntl->connection_type() == CONNECTION_TYPE_UNKNOWN) {
        cntl->set_connection_type(_options.connection_type);
    }
    cntl->_response = response;
    cntl->_done = done;
    cntl->_pack_request = _pack_request;
    cntl->_method = method;
    cntl->_auth = _options.auth;
    cntl->_single_server_id = _server_id;
    cntl->_remote_side = _server_address;

    if (cntl->FailedInline()) {
        // probably failed before RPC, not called until all necessary
        // parameters in `cntl' are set.
        return cntl->HandleSendFailed();
    }
    _serialize_request(&cntl->_request_buf, cntl, request);
    if (cntl->FailedInline()) {
        return cntl->HandleSendFailed();
    }

    if (cntl->timeout_ms() >= 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Set timeout event in channel";
        // Setup timer for RPC timetout

        // _deadline_us is for truncating _connect_timeout_ms
        cntl->_deadline_us = cntl->timeout_ms() * 1000L + start_send_real_us;
        const int rc = bthread_timer_add(
            &cntl->_timeout_id,
            sgxbutil::microseconds_to_timespec(cntl->_deadline_us),
            HandleTimeout, (void*)correlation_id.value);
        if (BAIDU_UNLIKELY(rc != 0)) {
            cntl->SetFailed(rc, "Fail to add timer for timeout");
            return cntl->HandleSendFailed();
        }
    } else {
        cntl->_deadline_us = -1;
    }

    cntl->IssueRPC(start_send_real_us);
    if (done == NULL) {
        // MUST wait for response when sending synchronous RPC. It will
        // be woken up by callback when RPC finishes (succeeds or still
        // fails after retry)
        Join(correlation_id);
        cntl->OnRPCEnd(sgxbutil::gettimeofday_us());
    }
}

void Channel::Describe(std::ostream& os, const DescribeOptions& opt) const {
    os << "Channel[";
    os << _server_address;
    os << "]";
}


int Channel::CheckHealth() {
    SocketUniquePtr ptr;
    if (Socket::Address(_server_id, &ptr) == 0 && ptr->IsAvailable()) {
        return 0;
    }
    return -1;
}

} // namespace brpc
