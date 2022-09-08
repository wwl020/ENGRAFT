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


#include "google/protobuf/descriptor.h"         // MethodDescriptor
#include "google/protobuf/message.h"            // Message
#include "google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "google/protobuf/io/coded_stream.h"
#include "sgxbutil/logging.h"                       // LOG()
#include "sgxbutil/time.h"
#include "sgxbutil/iobuf.h"                         // sgxbutil::IOBuf
#include "sgxbutil/raw_pack.h"                      // RawPacker RawUnpacker
#include "brpc/controller.h"                    // Controller
#include "brpc/socket.h"                        // Socket
#include "brpc/server.h"                        // Server
#include "brpc/compress.h"                      // ParseFromCompressedData
#include "brpc/policy/baidu_rpc_meta.pb.h"      // RpcRequestMeta
#include "brpc/policy/baidu_rpc_protocol.h"
#include "brpc/policy/most_common_message.h"
#include "brpc/details/controller_private_accessor.h"
#include "brpc/details/server_private_accessor.h"


namespace brpc {
namespace policy {

DEFINE_bool(baidu_protocol_use_fullname, true,
            "If this flag is true, baidu_std puts service.full_name in requests"
            ", otherwise puts service.name (required by jprotobuf).");

// Notes:
// 1. 12-byte header [PRPC][body_size][meta_size]
// 2. body_size and meta_size are in network byte order
// 3. Use service->full_name() + method_name to specify the method to call
// 4. `attachment_size' is set iff request/response has attachment
// 5. Not supported: chunk_info

// Pack header into `buf'
inline void PackRpcHeader(char* rpc_header, int meta_size, int payload_size) {
    uint32_t* dummy = (uint32_t*)rpc_header;  // suppress strict-alias warning
    *dummy = *(uint32_t*)"PRPC";
    sgxbutil::RawPacker(rpc_header + 4)
        .pack32(meta_size + payload_size)
        .pack32(meta_size);
}

static void SerializeRpcHeaderAndMeta(
    sgxbutil::IOBuf* out, const RpcMeta& meta, int payload_size) {
    const int meta_size = meta.ByteSize();
    if (meta_size <= 244) { // most common cases
        char header_and_meta[12 + meta_size];
        PackRpcHeader(header_and_meta, meta_size, payload_size);
        ::google::protobuf::io::ArrayOutputStream arr_out(header_and_meta + 12, meta_size);
        ::google::protobuf::io::CodedOutputStream coded_out(&arr_out);
        meta.SerializeWithCachedSizes(&coded_out); // not calling ByteSize again
        CHECK(!coded_out.HadError());
        out->append(header_and_meta, sizeof(header_and_meta));
    } else {
        char header[12];
        PackRpcHeader(header, meta_size, payload_size);
        out->append(header, sizeof(header));
        sgxbutil::IOBufAsZeroCopyOutputStream buf_stream(out);
        ::google::protobuf::io::CodedOutputStream coded_out(&buf_stream);
        meta.SerializeWithCachedSizes(&coded_out);
        CHECK(!coded_out.HadError());
    }
}

ParseResult ParseRpcMessage(sgxbutil::IOBuf* source, Socket* socket,
                            bool /*read_eof*/, const void*) {
    LOG(INFO) << __FUNCTION__ << " pthread-" << pthread_self();                              
    char header_buf[12];
    const size_t n = source->copy_to(header_buf, sizeof(header_buf));
    if (n >= 4) {
        void* dummy = header_buf;
        if (*(const uint32_t*)dummy != *(const uint32_t*)"PRPC") {
            return MakeParseError(PARSE_ERROR_TRY_OTHERS);
        }
    } else {
        if (memcmp(header_buf, "PRPC", n) != 0) {
            return MakeParseError(PARSE_ERROR_TRY_OTHERS);
        }
    }
    if (n < sizeof(header_buf)) {
        return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    }
    uint32_t body_size;
    uint32_t meta_size;
    sgxbutil::RawUnpacker(header_buf + 4).unpack32(body_size).unpack32(meta_size);
    if (body_size > FLAGS_max_body_size) {
        // We need this log to report the body_size to give users some clues
        // which is not printed in InputMessenger.
        LOG(ERROR) << "body_size=" << body_size << " from "
                   << socket->remote_side() << " is too large";
        return MakeParseError(PARSE_ERROR_TOO_BIG_DATA);
    } else if (source->length() < sizeof(header_buf) + body_size) {
        return MakeParseError(PARSE_ERROR_NOT_ENOUGH_DATA);
    }
    if (meta_size > body_size) {
        LOG(ERROR) << "meta_size=" << meta_size << " is bigger than body_size="
                   << body_size;
        // Pop the message
        source->pop_front(sizeof(header_buf) + body_size);
        return MakeParseError(PARSE_ERROR_TRY_OTHERS);
    }
    source->pop_front(sizeof(header_buf));
    MostCommonMessage* msg = MostCommonMessage::Get();
    source->cutn(&msg->meta, meta_size);
    source->cutn(&msg->payload, body_size - meta_size);
    return MakeMessage(msg);
}

// Used by UT, can't be static.
void SendRpcResponse(int64_t correlation_id,
                     Controller* cntl, 
                     const google::protobuf::Message* req,
                     const google::protobuf::Message* res,
                     const Server* server,
                     MethodStatus* method_status,
                     int64_t received_us) {
    ControllerPrivateAccessor accessor(cntl);
    Socket* sock = accessor.get_sending_socket();
    std::unique_ptr<Controller, LogErrorTextAndDelete> recycle_cntl(cntl);
    ConcurrencyRemover concurrency_remover(method_status, cntl, received_us);
    std::unique_ptr<const google::protobuf::Message> recycle_req(req);
    std::unique_ptr<const google::protobuf::Message> recycle_res(res);
    

    if (cntl->IsCloseConnection()) {
        sock->SetFailed();
        return;
    }
    bool append_body = false;
    sgxbutil::IOBuf res_body;
    // `res' can be NULL here, in which case we don't serialize it
    // If user calls `SetFailed' on Controller, we don't serialize
    // response either
    CompressType type = cntl->response_compress_type();
    if (res != NULL && !cntl->Failed()) {
        if (!res->IsInitialized()) {
            cntl->SetFailed(
                ERESPONSE, "Missing required fields in response: %s", 
                res->InitializationErrorString().c_str());
        } else if (!SerializeAsCompressedData(*res, &res_body, type)) {
            cntl->SetFailed(ERESPONSE, "Fail to serialize response, "
                            "CompressType=%s", CompressTypeToCStr(type));
        } else {
            append_body = true;
        }
    }

    // Don't use res->ByteSize() since it may be compressed
    size_t res_size = 0;
    size_t attached_size = 0;
    if (append_body) {
        res_size = res_body.length();
        attached_size = cntl->response_attachment().length();
    }

    int error_code = cntl->ErrorCode();
    if (error_code == -1) {
        // replace general error (-1) with INTERNAL_SERVER_ERROR to make a
        // distinction between server error and client error
        error_code = EINTERNAL;
    }
    RpcMeta meta;
    RpcResponseMeta* response_meta = meta.mutable_response();
    response_meta->set_error_code(error_code);
    if (!cntl->ErrorText().empty()) {
        // Only set error_text when it's not empty since protobuf Message
        // always new the string no matter if it's empty or not.
        response_meta->set_error_text(cntl->ErrorText());
    }
    meta.set_correlation_id(correlation_id);
    meta.set_compress_type(cntl->response_compress_type());
    if (attached_size > 0) {
        meta.set_attachment_size(attached_size);
    }

    sgxbutil::IOBuf res_buf;
    SerializeRpcHeaderAndMeta(&res_buf, meta, res_size + attached_size);
    if (append_body) {
        res_buf.append(res_body.movable());
        if (attached_size) {
            res_buf.append(cntl->response_attachment().movable());
        }
    }
    
    // Have the risk of unlimited pending responses, in which case, tell
    // users to set max_concurrency.
    Socket::WriteOptions wopt;
    wopt.ignore_eovercrowded = true;
    if (sock->Write(&res_buf, &wopt) != 0) {
        const int errcode = errno;
        PLOG_IF(WARNING, errcode != EPIPE) << "Fail to write into " << *sock;
        cntl->SetFailed(errcode, "Fail to write into %s",
                        sock->description().c_str());
        return;
    }
}

struct CallMethodInBackupThreadArgs {
    ::google::protobuf::Service* service;
    const ::google::protobuf::MethodDescriptor* method;
    ::google::protobuf::RpcController* controller;
    const ::google::protobuf::Message* request;
    ::google::protobuf::Message* response;
    ::google::protobuf::Closure* done;
};

static void CallMethodInBackupThread(void* void_args) {
    CallMethodInBackupThreadArgs* args = (CallMethodInBackupThreadArgs*)void_args;
    args->service->CallMethod(args->method, args->controller, args->request,
                              args->response, args->done);
    delete args;
}

//- TODO: 这个函数没有被使用，后续可以移除
// Used by other protocols as well.
// void EndRunningCallMethodInPool(
//     ::google::protobuf::Service* service,
//     const ::google::protobuf::MethodDescriptor* method,
//     ::google::protobuf::RpcController* controller,
//     const ::google::protobuf::Message* request,
//     ::google::protobuf::Message* response,
//     ::google::protobuf::Closure* done) {
//     CallMethodInBackupThreadArgs* args = new CallMethodInBackupThreadArgs;
//     args->service = service;
//     args->method = method;
//     args->controller = controller;
//     args->request = request;
//     args->response = response;
//     args->done = done;
//     return EndRunningUserCodeInPool(CallMethodInBackupThread, args);
// };

void ProcessRpcRequest(InputMessageBase* msg_base) {    
    DestroyingPtr<MostCommonMessage> msg(static_cast<MostCommonMessage*>(msg_base));
    SocketUniquePtr socket_guard(msg->ReleaseSocket());
    Socket* socket = socket_guard.get();
    const Server* server = static_cast<const Server*>(msg_base->arg());
    ScopedNonServiceError non_service_error(server);

    RpcMeta meta;
    if (!ParsePbFromIOBuf(&meta, msg->meta)) {
        LOG(WARNING) << "Fail to parse RpcMeta from " << *socket;
        socket->SetFailed(EREQUEST, "Fail to parse RpcMeta from %s",
                          socket->description().c_str());
        return;
    }
    
    const RpcRequestMeta &request_meta = meta.request();

    LOG(INFO) << __FUNCTION__ << " remote = " << socket->remote_side() << " remote id = " << meta.correlation_id() << " service name = " << request_meta.service_name() << " method name = " << request_meta.method_name();  

    std::unique_ptr<Controller> cntl(new (std::nothrow) Controller);
    if (NULL == cntl.get()) {
        LOG(WARNING) << "Fail to new Controller";
        return;
    }
    std::unique_ptr<google::protobuf::Message> req;
    std::unique_ptr<google::protobuf::Message> res;

    ServerPrivateAccessor server_accessor(server);
    ControllerPrivateAccessor accessor(cntl.get());
    const bool security_mode = server->options().security_mode() &&
                               socket->user() == server_accessor.acceptor();
    if (request_meta.has_log_id()) {
        cntl->set_log_id(request_meta.log_id());
    }
    cntl->set_request_compress_type((CompressType)meta.compress_type());
    accessor.set_server(server)
        .set_security_mode(security_mode)
        .set_peer_id(socket->id())
        .set_remote_side(socket->remote_side())
        .set_local_side(socket->local_side())
        .set_auth_context(socket->auth_context())
        .set_request_protocol(PROTOCOL_BAIDU_STD)
        .set_begin_time_us(msg->received_us())
        .move_in_server_receiving_sock(socket_guard);



    MethodStatus* method_status = NULL;
    do {
        if (!server->IsRunning()) {
            cntl->SetFailed(ELOGOFF, "Server is stopping");
            break;
        }

        if (socket->is_overcrowded()) {
            cntl->SetFailed(EOVERCROWDED, "Connection to %s is overcrowded",
                            sgxbutil::endpoint2str(socket->remote_side()).c_str());
            break;
        }
        
        if (!server_accessor.AddConcurrency(cntl.get())) {
            cntl->SetFailed(
                ELIMIT, "Reached server's max_concurrency=%d",
                server->options().max_concurrency);
            break;
        }

        // NOTE(gejun): jprotobuf sends service names without packages. So the
        // name should be changed to full when it's not.
        sgxbutil::StringPiece svc_name(request_meta.service_name());
        if (svc_name.find('.') == sgxbutil::StringPiece::npos) {
            const Server::ServiceProperty* sp =
                server_accessor.FindServicePropertyByName(svc_name);
            if (NULL == sp) {
                cntl->SetFailed(ENOSERVICE, "Fail to find service=%s",
                                request_meta.service_name().c_str());
                break;
            }
            svc_name = sp->service->GetDescriptor()->full_name();
        }
        const Server::MethodProperty* mp =
            server_accessor.FindMethodPropertyByFullName(
                svc_name, request_meta.method_name());
        if (NULL == mp) {
            cntl->SetFailed(ENOMETHOD, "Fail to find method=%s/%s",
                            request_meta.service_name().c_str(),
                            request_meta.method_name().c_str());
            break;
        // } else if (mp->service->GetDescriptor()== BadMethodService::descriptor()) {
        } else if (0) {
            // BadMethodRequest breq;
            // BadMethodResponse bres;
            // breq.set_service_name(request_meta.service_name());
            // mp->service->CallMethod(mp->method, cntl.get(), &breq, &bres, NULL);
            break;
        }
        // Switch to service-specific error.
        non_service_error.release();
        method_status = mp->status;
        if (method_status) {
            int rejected_cc = 0;
            if (!method_status->OnRequested(&rejected_cc)) {
                cntl->SetFailed(ELIMIT, "Rejected by %s's ConcurrencyLimiter, concurrency=%d",
                                mp->method->full_name().c_str(), rejected_cc);
                break;
            }
        }
        google::protobuf::Service* svc = mp->service;
        const google::protobuf::MethodDescriptor* method = mp->method;
        accessor.set_method(method);
        const int reqsize = static_cast<int>(msg->payload.size());
        sgxbutil::IOBuf req_buf;
        sgxbutil::IOBuf* req_buf_ptr = &msg->payload;
        if (meta.has_attachment_size()) {
            if (reqsize < meta.attachment_size()) {
                cntl->SetFailed(EREQUEST,
                    "attachment_size=%d is larger than request_size=%d",
                     meta.attachment_size(), reqsize);
                break;
            }
            int att_size = reqsize - meta.attachment_size();
            msg->payload.cutn(&req_buf, att_size);
            req_buf_ptr = &req_buf;
            cntl->request_attachment().swap(msg->payload);
        }

        CompressType req_cmp_type = (CompressType)meta.compress_type();
        req.reset(svc->GetRequestPrototype(method).New());
        if (!ParseFromCompressedData(*req_buf_ptr, req.get(), req_cmp_type)) {
            cntl->SetFailed(EREQUEST, "Fail to parse request message, "
                            "CompressType=%s, request_size=%d", 
                            CompressTypeToCStr(req_cmp_type), reqsize);
            break;
        }
        
        res.reset(svc->GetResponsePrototype(method).New());
        // `socket' will be held until response has been sent
        google::protobuf::Closure* done = ::brpc::NewCallback<
            int64_t, Controller*, const google::protobuf::Message*,
            const google::protobuf::Message*, const Server*,
            MethodStatus*, int64_t>(
                &SendRpcResponse, meta.correlation_id(), cntl.get(), 
                req.get(), res.get(), server,
                method_status, msg->received_us());

        // optional, just release resourse ASAP
        msg.reset();
        req_buf.clear();
        LOG(INFO) << "Func: " << __FUNCTION__ << " Will call svc->CallMethod";
        VLOG(80) << "Func: " << __FUNCTION__ << " Will call svc->CallMethod";
        return svc->CallMethod(method, cntl.release(), 
                                   req.release(), res.release(), done);
    } while (false);
    //- This may not happen in braft.
    LOG(INFO) << "Func: " << __FUNCTION__ << " Will call SendRpcResponse";
    
    // `cntl', `req' and `res' will be deleted inside `SendRpcResponse'
    // `socket' will be held until response has been sent
    SendRpcResponse(meta.correlation_id(), cntl.release(), 
                    req.release(), res.release(), server,
                    method_status, msg->received_us());
}

bool VerifyRpcRequest(const InputMessageBase* msg_base) {
    LOG(INFO) << __FUNCTION__ << " pthread-" << pthread_self();  
    const MostCommonMessage* msg =
        static_cast<const MostCommonMessage*>(msg_base);
    const Server* server = static_cast<const Server*>(msg->arg());
    Socket* socket = msg->socket();
    
    RpcMeta meta;
    if (!ParsePbFromIOBuf(&meta, msg->meta)) {
        LOG(WARNING) << "Fail to parse RpcRequestMeta";
        return false;
    }

    LOG(INFO) << __FUNCTION__ << " remote = " << socket->remote_side() << " remote id = " << meta.correlation_id() << " service name = " << meta.request().service_name() << " method name = " << meta.request().method_name(); 

    const Authenticator* auth = server->options().auth;
    if (NULL == auth) {
        // Fast pass (no authentication)
        return true;
    }    
    if (auth->VerifyCredential(
                meta.authentication_data(), socket->remote_side(), 
                socket->mutable_auth_context()) != 0) {
        return false;
    }
    return true;
}

void ProcessRpcResponse(InputMessageBase* msg_base) {
    
    DestroyingPtr<MostCommonMessage> msg(static_cast<MostCommonMessage*>(msg_base));
    RpcMeta meta;
    if (!ParsePbFromIOBuf(&meta, msg->meta)) {
        LOG(WARNING) << "Fail to parse from response meta";
        return;
    }
    //- TODO: 这里处理的是response，获取meta.request()是没有意义的，是空值
    LOG(INFO) << __FUNCTION__ << " from = " << msg->socket()->remote_side() << " id = " << meta.correlation_id() << " service name = " << meta.request().service_name() << " method name = " << meta.request().method_name(); 

    const bthread_id_t cid = { static_cast<uint64_t>(meta.correlation_id()) };
    Controller* cntl = NULL;
    const int rc = bthread_id_lock(cid, (void**)&cntl);
    if (rc != 0) {
        LOG_IF(ERROR, rc != EINVAL && rc != EPERM)
            << "Fail to lock correlation_id=" << cid << ": " << berror(rc);
        return;
    }
    ControllerPrivateAccessor accessor(cntl);
    const RpcResponseMeta &response_meta = meta.response();
    const int saved_error = cntl->ErrorCode();
    do {
        if (response_meta.error_code() != 0) {
            // If error_code is unset, default is 0 = success.
            cntl->SetFailed(response_meta.error_code(), 
                                  "%s", response_meta.error_text().c_str());
            break;
        } 
        // Parse response message iff error code from meta is 0
        sgxbutil::IOBuf res_buf;
        const int res_size = msg->payload.length();
        sgxbutil::IOBuf* res_buf_ptr = &msg->payload;
        if (meta.has_attachment_size()) {
            if (meta.attachment_size() > res_size) {
                cntl->SetFailed(
                    ERESPONSE,
                    "attachment_size=%d is larger than response_size=%d",
                    meta.attachment_size(), res_size);
                break;
            }
            int att_size = res_size - meta.attachment_size();
            msg->payload.cutn(&res_buf, att_size);
            res_buf_ptr = &res_buf;
            cntl->response_attachment().swap(msg->payload);
        }

        const CompressType res_cmp_type = (CompressType)meta.compress_type();
        cntl->set_response_compress_type(res_cmp_type);
        if (cntl->response()) {
            if (!ParseFromCompressedData(
                    *res_buf_ptr, cntl->response(), res_cmp_type)) {
                cntl->SetFailed(
                    ERESPONSE, "Fail to parse response message, "
                    "CompressType=%s, response_size=%d", 
                    CompressTypeToCStr(res_cmp_type), res_size);
            }
        } // else silently ignore the response.        
    } while (0);
    // Unlocks correlation_id inside. Revert controller's
    // error code if it version check of `cid' fails
    msg.reset();  // optional, just release resourse ASAP
    accessor.OnResponse(cid, saved_error);
}

void PackRpcRequest(sgxbutil::IOBuf* req_buf,
                    SocketMessage**,
                    uint64_t correlation_id,
                    const google::protobuf::MethodDescriptor* method,
                    Controller* cntl,
                    const sgxbutil::IOBuf& request_body,
                    const Authenticator* auth) {
    // LOG(INFO) << __FUNCTION__ << " Call ID = " << correlation_id;                        
    RpcMeta meta;
    if (auth && auth->GenerateCredential(
            meta.mutable_authentication_data()) != 0) {
        return cntl->SetFailed(EREQUEST, "Fail to generate credential");
    }

    ControllerPrivateAccessor accessor(cntl);
    RpcRequestMeta* request_meta = meta.mutable_request();
    if (method) {
        request_meta->set_service_name(FLAGS_baidu_protocol_use_fullname ?
                                       method->service()->full_name() :
                                       method->service()->name());
        request_meta->set_method_name(method->name());
        meta.set_compress_type(cntl->request_compress_type());
    } else {
        return cntl->SetFailed(ENOMETHOD, "%s.method is NULL", __FUNCTION__);
    }
    if (cntl->has_log_id()) {
        request_meta->set_log_id(cntl->log_id());
    }
    meta.set_correlation_id(correlation_id);

    // Don't use res->ByteSize() since it may be compressed
    const size_t req_size = request_body.length(); 
    const size_t attached_size = cntl->request_attachment().length();
    if (attached_size) {
        meta.set_attachment_size(attached_size);
    }

    SerializeRpcHeaderAndMeta(req_buf, meta, req_size + attached_size);
    req_buf->append(request_body);
    if (attached_size) {
        req_buf->append(cntl->request_attachment());
    }

    LOG(INFO) << __FUNCTION__ << " id = " << meta.correlation_id() << " service name = " << request_meta->service_name() << " method name = " << request_meta->method_name(); 
}

}  // namespace policy
} // namespace brpc
