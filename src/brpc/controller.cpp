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


#include <signal.h>
#include <openssl/md5.h>
#include "google/protobuf/descriptor.h"
#include "google/gflags/gflags.h"
#include "bthread/bthread.h"
#include "sgxbutil/string_printf.h"
#include "sgxbutil/logging.h"
#include "sgxbutil/time.h"
#include "bthread/bthread.h"
#include "bthread/unstable.h"
// #include "bvar/bvar.h"
#include "brpc/socket.h"
#include "brpc/socket_map.h"
#include "brpc/channel.h"
#include "brpc/closure_guard.h"
#include "brpc/details/controller_private_accessor.h"
#include "brpc/controller.h"
#include "brpc/server.h" 
#include "bthread/bthread.h"
#include "bthread/unstable.h"

// This is the only place that both client/server must link, so we put
// registrations of errno here.
BAIDU_REGISTER_ERRNO(brpc::ENOSERVICE, "No such service");
BAIDU_REGISTER_ERRNO(brpc::ENOMETHOD, "No such method");
BAIDU_REGISTER_ERRNO(brpc::EREQUEST, "Bad request");
BAIDU_REGISTER_ERRNO(brpc::ERPCAUTH, "Authentication failed");
BAIDU_REGISTER_ERRNO(brpc::ETOOMANYFAILS, "Too many sub channels failed");
BAIDU_REGISTER_ERRNO(brpc::EPCHANFINISH, "ParallelChannel finished");
BAIDU_REGISTER_ERRNO(brpc::ERPCTIMEDOUT, "RPC call is timed out");
BAIDU_REGISTER_ERRNO(brpc::EFAILEDSOCKET, "Broken socket");
BAIDU_REGISTER_ERRNO(brpc::EHTTP, "Bad http call");
BAIDU_REGISTER_ERRNO(brpc::EOVERCROWDED, "The server is overcrowded");
BAIDU_REGISTER_ERRNO(brpc::ERTMPPUBLISHABLE, "RtmpRetryingClientStream is publishable");
BAIDU_REGISTER_ERRNO(brpc::ERTMPCREATESTREAM, "createStream was rejected by the RTMP server");
BAIDU_REGISTER_ERRNO(brpc::EEOF, "Got EOF");
BAIDU_REGISTER_ERRNO(brpc::EUNUSED, "The socket was not needed");
BAIDU_REGISTER_ERRNO(brpc::ESSL, "SSL related operation failed");
BAIDU_REGISTER_ERRNO(brpc::EH2RUNOUTSTREAMS, "The H2 socket was run out of streams");

BAIDU_REGISTER_ERRNO(brpc::EINTERNAL, "General internal error");
BAIDU_REGISTER_ERRNO(brpc::ERESPONSE, "Bad response");
BAIDU_REGISTER_ERRNO(brpc::ELOGOFF, "Server is stopping");
BAIDU_REGISTER_ERRNO(brpc::ELIMIT, "Reached server's max_concurrency");
BAIDU_REGISTER_ERRNO(brpc::ECLOSE, "Close socket initiatively");
BAIDU_REGISTER_ERRNO(brpc::EITP, "Bad Itp response");


namespace brpc {

DEFINE_bool(graceful_quit_on_sigterm, false, "Register SIGTERM handle func to quit graceful");

const IdlNames idl_single_req_single_res = { "req", "res" };
const IdlNames idl_single_req_multi_res = { "req", "" };
const IdlNames idl_multi_req_single_res = { "", "res" };
const IdlNames idl_multi_req_multi_res = { "", "" };

extern const int64_t IDL_VOID_RESULT = 12345678987654321LL;

// For definitely false branch in src/brpc/profiler_link.h
int PROFILER_LINKER_DUMMY = 0;

static void PrintRevision(std::ostream& os, void*) {
#if defined(BRPC_REVISION)
    os << BRPC_REVISION;
#else
    os << "undefined";
#endif
}
// static bvar::PassiveStatus<std::string> s_rpc_revision(
//     "rpc_revision", PrintRevision, NULL);


DECLARE_bool(usercode_in_pthread);
static const int MAX_RETRY_COUNT = 1000;
// static bvar::Adder<int64_t>* g_ncontroller = NULL;

static pthread_once_t s_create_vars_once = PTHREAD_ONCE_INIT;

static void CreateVars() {
    // g_ncontroller = new bvar::Adder<int64_t>("rpc_controller_count");
}

Controller::Controller() {
    CHECK_EQ(0, pthread_once(&s_create_vars_once, CreateVars));
    // *g_ncontroller << 1;
    ResetPods();
}

Controller::~Controller() {
    // *g_ncontroller << -1;
    ResetNonPods();
}

// If resource needs to be destroyed or memory needs to be deleted (both
// directly and indirectly referenced), do them in this method. Notice that
// you don't have to set the fields to initial state after deletion since
// they'll be set uniformly after this method is called.
void Controller::ResetNonPods() {
    _error_text.clear();
    _remote_side = sgxbutil::EndPoint();
    _local_side = sgxbutil::EndPoint();

    if (!is_used_by_rpc() && _correlation_id != INVALID_BTHREAD_ID) {
        CHECK_NE(EPERM, bthread_id_cancel(_correlation_id));
    }

    _current_call.Reset();
    _request_buf.clear();
    delete _http_request;
    delete _http_response;
    _request_attachment.clear();
    _response_attachment.clear();

    _thrift_method_name.clear();
}

//- In computer science and object-oriented programming, a passive data structure (PDS, also termed a plain old data structure, or plain old data, POD) is a term for a record, to contrast with objects. It is a data structure that is represented only as passive collections of field values (instance variables), without using object-oriented features.
void Controller::ResetPods() {
    // NOTE: Make the sequence of assignments same with the order that they're
    // defined in header. Better for cpu cache and faster for lookup.
    _flags = 0;
#ifndef BAIDU_INTERNAL
    set_pb_bytes_to_base64(true);
#endif
    _error_code = 0;
    _server = NULL;
    _auth_context = NULL;
    _request_protocol = PROTOCOL_UNKNOWN;
    _max_retry = UNSET_MAGIC_NUM;
    _correlation_id = INVALID_BTHREAD_ID;
    _connection_type = CONNECTION_TYPE_UNKNOWN;
    _timeout_ms = UNSET_MAGIC_NUM;
    _connect_timeout_ms = UNSET_MAGIC_NUM;
    _deadline_us = -1;
    _timeout_id = 0;
    _begin_time_us = 0;
    _end_time_us = 0;
    _tos = 0;
    _preferred_index = -1;
    _request_compress_type = COMPRESS_TYPE_NONE;
    _response_compress_type = COMPRESS_TYPE_NONE;
    _fail_limit = UNSET_MAGIC_NUM;
    _pipelined_count = 0;
    _log_id = 0;
    _response = NULL;
    _done = NULL;
    _request_code = 0;
    _single_server_id = INVALID_SOCKET_ID;
    _stream_creator = NULL;
    _pack_request = NULL;
    _method = NULL;
    _auth = NULL;
    _idl_names = idl_single_req_single_res;
    _idl_result = IDL_VOID_RESULT;
    _http_request = NULL;
    _http_response = NULL;
}

Controller::Call::Call(Controller::Call* rhs)
    : nretry(rhs->nretry)
    , peer_id(rhs->peer_id)
    , begin_time_us(rhs->begin_time_us)
    , sending_sock(rhs->sending_sock.release())
    , stream_user_data(rhs->stream_user_data) {
    // NOTE: fields in rhs should be reset because RPC could fail before
    // setting all the fields to next call and _current_call.OnComplete
    // will behave incorrectly.
    rhs->peer_id = INVALID_SOCKET_ID;
    rhs->stream_user_data = NULL;
}

Controller::Call::~Call() {
    CHECK(sending_sock.get() == NULL);
}

void Controller::Call::Reset() {
    nretry = 0;
    peer_id = INVALID_SOCKET_ID;
    begin_time_us = 0;
    sending_sock.reset(NULL);
    stream_user_data = NULL;
}

void Controller::set_timeout_ms(int64_t timeout_ms) {
    if (timeout_ms <= 0x7fffffff) {
        _timeout_ms = timeout_ms;
    } else {
        _timeout_ms = 0x7fffffff;
        LOG(WARNING) << "timeout_ms is limited to 0x7fffffff (roughly 24 days)";
    }
}


void Controller::set_max_retry(int max_retry) {
    //- TODO: 在sgx-braft里面，rpc不需要重试，所以永远将重试次数设置为0
    //- 不直接将max_retry的相关定义移除，是为了暂时保留和重试相关的接口（braft里面用到）简化开发
    //- 简而言之，就是现在暂时不想动braft
    //- 后续再将max_retry的相关定义和用例移除 05.14
    _max_retry = 0;
    return;

    // if (max_retry > MAX_RETRY_COUNT) {
    //     LOG(WARNING) << "Retry count can't be larger than "
    //                  << MAX_RETRY_COUNT << ", round it to "
    //                  << MAX_RETRY_COUNT;
    //     _max_retry = MAX_RETRY_COUNT;
    // } else {
    //     _max_retry = max_retry;
    // }
}

void Controller::set_log_id(uint64_t log_id) {
    add_flag(FLAGS_LOG_ID);
    _log_id = log_id;
}


bool Controller::Failed() const {
    return FailedInline();
}

std::string Controller::ErrorText() const {
    return _error_text;
}

void StartCancel(CallId id) {
    bthread_id_error(id, ECANCELED);
}

void Controller::StartCancel() {
    LOG(FATAL) << "You must call brpc::StartCancel(id) instead!"
        " because this function is racing with ~Controller() in "
        " asynchronous calls.";
}

static const char HEX_ALPHA[] = "0123456789ABCDEF";
void Controller::AppendServerIdentiy() {
    if (_server == NULL) {
        return;
    }
    if (is_security_mode()) {
        _error_text.reserve(_error_text.size() + MD5_DIGEST_LENGTH * 2 + 2);
        _error_text.push_back('[');
        char ipbuf[64];
        int len = snprintf(ipbuf, sizeof(ipbuf), "%s:%d",
                           sgxbutil::my_ip_cstr(), _server->listen_address().port);
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((const unsigned char*)ipbuf, len, digest);
        for (size_t i = 0; i < sizeof(digest); ++i) {
            _error_text.push_back(HEX_ALPHA[digest[i] & 0xF]);
            _error_text.push_back(HEX_ALPHA[digest[i] >> 4]);
        }
        _error_text.push_back(']');
    } else {
        sgxbutil::string_appendf(&_error_text, "[%s:%d]",
                             sgxbutil::my_ip_cstr(), _server->listen_address().port);
    }
}

inline void UpdateResponseHeader(Controller* cntl) {
    DCHECK(cntl->Failed());
    if (cntl->request_protocol() == PROTOCOL_HTTP ||
        cntl->request_protocol() == PROTOCOL_H2) {
        if (cntl->ErrorCode() != EHTTP) {
            // Set the related status code
            cntl->http_response().set_status_code(
                ErrorCodeToStatusCode(cntl->ErrorCode()));
        } // else assume that status code is already set along with EHTTP.
        if (cntl->server() != NULL) {
            // Override HTTP body at server-side to conduct error text
            // to the client.
            // The client-side should preserve body which may be a piece
            // of useable data rather than error text.
            cntl->response_attachment().clear();
            cntl->response_attachment().append(cntl->ErrorText());
        }
    }
}

void Controller::SetFailed(const std::string& reason) {
    _error_code = -1;
    if (!_error_text.empty()) {
        _error_text.push_back(' ');
    }
    if (_current_call.nretry != 0) {
        sgxbutil::string_appendf(&_error_text, "[R%d]", _current_call.nretry);
    } else {
        AppendServerIdentiy();
    }
    _error_text.append(reason);
    UpdateResponseHeader(this);
}

void Controller::SetFailed(int error_code, const char* reason_fmt, ...) {
    if (error_code == 0) {
        CHECK(false) << "error_code is 0";
        error_code = -1;
    }
    _error_code = error_code;
    if (!_error_text.empty()) {
        _error_text.push_back(' ');
    }
    if (_current_call.nretry != 0) {
        sgxbutil::string_appendf(&_error_text, "[R%d]", _current_call.nretry);
    } else {
        AppendServerIdentiy();
    }
    const size_t old_size = _error_text.size();
    if (_error_code != -1) {
        sgxbutil::string_appendf(&_error_text, "[E%d]", _error_code);
    }
    va_list ap;
    va_start(ap, reason_fmt);
    sgxbutil::string_vappendf(&_error_text, reason_fmt, ap);
    va_end(ap);
    UpdateResponseHeader(this);
}

void Controller::CloseConnection(const char* reason_fmt, ...) {
    if (_error_code == 0) {
        _error_code = ECLOSE;
    }
    add_flag(FLAGS_CLOSE_CONNECTION);
    if (!_error_text.empty()) {
        _error_text.push_back(' ');
    }
    if (_current_call.nretry != 0) {
        sgxbutil::string_appendf(&_error_text, "[R%d]", _current_call.nretry);
    } else {
        AppendServerIdentiy();
    }
    const size_t old_size = _error_text.size();
    if (_error_code != -1) {
        sgxbutil::string_appendf(&_error_text, "[E%d]", _error_code);
    }
    va_list ap;
    va_start(ap, reason_fmt);
    sgxbutil::string_vappendf(&_error_text, reason_fmt, ap);
    va_end(ap);
    UpdateResponseHeader(this);
}

bool Controller::IsCanceled() const {
    SocketUniquePtr sock;
    return (Socket::Address(_current_call.peer_id, &sock) != 0);
}

void Controller::NotifyOnCancel(google::protobuf::Closure* callback) {
    //- This is an empty function since it is not called in sgx-braft.
    //- However, Controller must implement this function since it is inherited from google::protobuf::RpcController
}

//- TODO: 目前没有发现调用该函数的情况
void Join(CallId id) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " bthread-" << bthread_self() << "Joining RPC...";
    bthread_id_join(id);
}


void Controller::OnVersionedRPCReturned(const CompletionInfo& info,
                                        bool new_bthread, int saved_error) {
    // TODO(gejun): Simplify call-ending code.
    // Intercept previous calls
    LOG(INFO) << "Func: " << __FUNCTION__ << " bthread-" << bthread_self() << " *** info.id = " << info.id << " _correlation_id = " << _correlation_id << " call_id() = " << call_id() << " current_id() = " << current_id();
    while (info.id != _correlation_id && info.id != current_id()) {
        //- Ignore requestes that don't match id
        _error_code = saved_error;
        response_attachment().clear();
        CHECK_EQ(0, bthread_id_unlock(info.id));
        return;
    }

    if (new_bthread) {
        // [ Essential for -usercode_in_pthread=true ]
        // When -usercode_in_pthread is on, the reserved threads (set by
        // -usercode_backup_threads) may all block on bthread_id_lock in
        // ProcessXXXResponse(), until the id is unlocked or destroyed which
        // is run in a new thread when new_bthread is true. However since all
        // workers are blocked, the created bthread will never be scheduled
        // and result in deadlock.
        // Make the id unlockable before creating the bthread fixes the issue.
        // When -usercode_in_pthread is false, this also removes some useless
        // waiting of the bthreads processing responses.

        // Note[_done]: callid is destroyed after _done which possibly takes
        // a lot of time, stop useless locking

        // Note[cid]: When the callid needs to be destroyed in done->Run(),
        // it does not mean that it will be destroyed directly in done->Run(),
        // conversely the callid may still be locked/unlocked for many times
        // before destroying. E.g. in slective channel, the callid is referenced
        // by multiple sub-done and only destroyed by the last one. Calling
        // bthread_id_about_to_destroy right here which makes the id unlockable
        // anymore, is wrong. On the other hand, the combo channles setting
        // FLAGS_DESTROY_CID_IN_DONE to true must be aware of
        // -usercode_in_pthread and avoid deadlock by their own (TBR)

        if ((FLAGS_usercode_in_pthread || _done != NULL/*Note[_done]*/) &&
            !has_flag(FLAGS_DESTROY_CID_IN_DONE)/*Note[cid]*/) {
            bthread_id_about_to_destroy(info.id);
        }
        // No need to join this bthread since RPC caller won't wake up
        // (or user's done won't be called) until this bthread finishes
        bthread_t bt;
        bthread_attr_t attr = (FLAGS_usercode_in_pthread ?
                               BTHREAD_ATTR_PTHREAD : BTHREAD_ATTR_NORMAL);
        _tmp_completion_info = info;
        if (bthread_start_background(&bt, &attr, RunEndRPC, this) != 0) {
            LOG(FATAL) << "Fail to start bthread";
            EndRPC(info);
        }
    } else {
        if (_done != NULL/*Note[_done]*/ &&
            !has_flag(FLAGS_DESTROY_CID_IN_DONE)/*Note[cid]*/) {
            bthread_id_about_to_destroy(info.id);
        }
        EndRPC(info);
    }
}

void* Controller::RunEndRPC(void* arg) {
    Controller* c = static_cast<Controller*>(arg);
    c->EndRPC(c->_tmp_completion_info);
    return NULL;
}

inline bool does_error_affect_main_socket(int error_code) {
    // Errors tested in this function are reported by pooled connections
    // and very likely to indicate that the server-side is down and the socket
    // should be health-checked.
    return error_code == ECONNREFUSED ||
        error_code == ENETUNREACH ||
        error_code == EHOSTUNREACH ||
        error_code == EINVAL/*returned by connect "0.0.0.1"*/;
}

//Note: A RPC call is probably consisted by several individual Calls such as
//      retries and backup requests. This method simply cares about the error of
//      this very Call (specified by |error_code|) rather than the error of the
//      entire RPC (specified by c->FailedInline()).
void Controller::Call::OnComplete(
        Controller* c, int error_code/*note*/, bool responded, bool end_of_rpc) {
    if (stream_user_data) {
        stream_user_data->DestroyStreamUserData(sending_sock, c, error_code, end_of_rpc);
        stream_user_data = NULL;
    }

    if (sending_sock != NULL) {
        if (error_code != 0) {
            sending_sock->AddRecentError();
        }
    }

    switch (c->connection_type()) {
    case CONNECTION_TYPE_UNKNOWN:
        break;
    case CONNECTION_TYPE_SINGLE:
        // Set main socket to be failed for connection refusal of streams.
        // "single" streams are often maintained in a separate SocketMap and
        // different from the main socket as well.
        if (c->_stream_creator != NULL &&
            does_error_affect_main_socket(error_code) &&
            (sending_sock == NULL || sending_sock->id() != peer_id)) {
            Socket::SetFailed(peer_id);
        }
        break;
    case CONNECTION_TYPE_POOLED:
        // NOTE: Not reuse pooled connection if this call fails and no response
        // has been received through this connection
        // Otherwise in-flight responses may come back in future and break the
        // assumption that one pooled connection cannot have more than one
        // message at the same time.
        if (sending_sock != NULL && (error_code == 0 || responded)) {
            // Normally-read socket which will not be used after RPC ends,
            // safe to return. Notice that Socket::is_read_progressive may
            // differ from Controller::is_response_read_progressively()
            // because RPC possibly ends before setting up the socket.
            sending_sock->ReturnToPool();           
            break;
        }
        // fall through
    case CONNECTION_TYPE_SHORT:
        if (sending_sock != NULL) {
            // Check the comment in CONNECTION_TYPE_POOLED branch.
            if (c->_stream_creator == NULL) {
                sending_sock->SetFailed();
            }
        }
        if (does_error_affect_main_socket(error_code)) {
            // main socket should die as well.
            // NOTE: main socket may be wrongly set failed (provided that
            // short/pooled socket does not hold a ref of the main socket).
            // E.g. an in-parallel RPC sets the peer_id to be failed
            //   -> this RPC meets ECONNREFUSED
            //   -> main socket gets revived from HC
            //   -> this RPC sets main socket to be failed again.
            Socket::SetFailed(peer_id);
        }
        break;
    }

    if (ELOGOFF == error_code) {
        SocketUniquePtr sock;
        if (Socket::Address(peer_id, &sock) == 0) {
            // Block this `Socket' while not closing the fd
            sock->SetLogOff();
        }
    }

    // Release the `Socket' we used to send/receive data
    sending_sock.reset(NULL);
}

void Controller::EndRPC(const CompletionInfo& info) {
    //- DEAL WITH CONTROLLER MUTEX
    //- TODO: 尝试改写bthread id，暂时不开启rpc超时，注释了以下4行
    if (_timeout_id != 0) {
        bthread_timer_del(_timeout_id);
        _timeout_id = 0;
    }

    // End _current_call.
    if (info.id == current_id() || info.id == _correlation_id) {
        if (_current_call.sending_sock != NULL) {
            _remote_side = _current_call.sending_sock->remote_side();
            _local_side = _current_call.sending_sock->local_side();
        }

        _current_call.OnComplete(this, _error_code, info.responded, true);
    } else {
        CHECK(false) << "A previous request responded, cid="
                        << info.id << " current_cid=" << current_id()
                        << " initial_cid=" << _correlation_id
                        << " stream_user_data=" << _current_call.stream_user_data
                        << " sending_sock=" << _current_call.sending_sock.get();
        _current_call.OnComplete(this, ECANCELED, false, false);       
    }

    if (_stream_creator) {
        _stream_creator->DestroyStreamCreator(this);
        _stream_creator = NULL;
    }
    // Clear _error_text when the call succeeded, otherwise a successful
    // call with non-empty ErrorText may confuse user.
    if (!_error_code) {
        _error_text.clear();
    }

    // No need to retry or can't retry, just call user's `done'.
    const CallId saved_cid = _correlation_id;
    if (_done) {
        if (!FLAGS_usercode_in_pthread || _done == DoNothing()/*Note*/) {
            // Note: no need to run DoNothing in backup thread when pthread
            // mode is on. Otherwise there's a tricky deadlock:
            // void SomeService::CallMethod(...) { // -usercode_in_pthread=true
            //   ...
            //   channel.CallMethod(...., brpc::DoNothing());
            //   brpc::Join(cntl.call_id());
            //   ...
            // }
            // Join is not signalled when the done does not Run() and the done
            // can't Run() because all backup threads are blocked by Join().

            OnRPCEnd(sgxbutil::gettimeofday_us());
            const bool destroy_cid_in_done = has_flag(FLAGS_DESTROY_CID_IN_DONE);
            LOG(INFO) << "Func: " << __FUNCTION__ << " bthread-" << bthread_self() << " Run done in bthread, _correlation_id = " << saved_cid;
            _done->Run();
            // NOTE: Don't touch this Controller anymore, because it's likely to be
            // deleted by done.
            if (!destroy_cid_in_done) {
                // Make this thread not scheduling itself when launching new
                // bthreads, saving signalings.
                // FIXME: We're assuming the calling thread is about to quit.
                bthread_about_to_quit();
                CHECK_EQ(0, bthread_id_unlock_and_destroy(saved_cid));
            }
        } else {
            // RunUserCode(RunDoneInBackupThread, this);
        }
    } else {
        LOG(INFO) << "Func: " << __FUNCTION__ << " bthread-" << bthread_self() << " Sync RPC";
        // OnRPCEnd for sync RPC is called in Channel::CallMethod to count in
        // latency of the context-switch.

        // Check comments in above branch on bthread_about_to_quit.
        bthread_about_to_quit();
        CHECK_EQ(0, bthread_id_unlock_and_destroy(saved_cid));
    }
}


void Controller::HandleSendFailed() {
    if (!FailedInline()) {
        SetFailed("Must be SetFailed() before calling HandleSendFailed()");
        LOG(FATAL) << ErrorText();
    }
    const CompletionInfo info = { current_id(), false };
    // NOTE: Launch new thread to run the callback in an asynchronous call
    // (and done is not allowed to run in-place)
    // Users may hold a lock before asynchronus CallMethod returns and
    // grab the same lock inside done->Run(). If done->Run() is called in the
    // same stack of CallMethod, the code is deadlocked.
    // We don't need to run the callback in new thread in a sync call since
    // the created thread needs to be joined anyway before end of CallMethod.
    const bool new_bthread = (_done != NULL && !is_done_allowed_to_run_in_place());
    OnVersionedRPCReturned(info, new_bthread, _error_code);
}

void Controller::IssueRPC(int64_t start_realtime_us) {
    LOG(INFO) << __FUNCTION__ << " bthread-" << bthread_self() << " Call ID = " << call_id();
    _current_call.begin_time_us = start_realtime_us;
    // Clear last error, Don't clear _error_text because we append to it.
    _error_code = 0;

    // Make versioned correlation_id.
    // call_id         : unversioned, mainly for ECANCELED and ERPCTIMEDOUT
    // call_id + 1     : first try.
    // call_id + 2     : retry 1
    // ...
    // call_id + N + 1 : retry N
    // All ids except call_id are versioned. Say if we've sent retry 1 and
    // a failed response of first try comes back, it will be ignored.
    const CallId cid = current_id();

    // Pick a target server for sending RPC
    SocketUniquePtr tmp_sock;
    // Don't use _current_call.peer_id which is set to -1 after construction
    // of the backup call.
    LOG(INFO) << "Func: " << __FUNCTION__ << " bthread-" << bthread_self() << " _single_server_id = " << _single_server_id;
    const int ret_code = Socket::Address(_single_server_id, &tmp_sock);
    if (ret_code != 0 || (!is_health_check_call() && !tmp_sock->IsAvailable())) {
        SetFailed(EHOSTDOWN, "Not connected to %s yet, server_id=%" PRIu64,
                    endpoint2str(_remote_side).c_str(), _single_server_id);
        tmp_sock.reset();  // Release ref ASAP
        return HandleSendFailed();
    }
    _current_call.peer_id = _single_server_id;
    if (_stream_creator) {
        LOG(INFO) << "_stream_creator is not NULL";
        _current_call.stream_user_data =
            _stream_creator->OnCreatingStream(&tmp_sock, this);
        if (FailedInline()) {
            return HandleSendFailed();
        }
        // remote_side can't be changed.
        CHECK_EQ(_remote_side, tmp_sock->remote_side());
    }

    // Handle connection type
    if (_connection_type == CONNECTION_TYPE_SINGLE ||
        _stream_creator != NULL) { // let user decides the sending_sock
        // in the callback(according to connection_type) directly
        _current_call.sending_sock.reset(tmp_sock.release());        
        LOG(INFO) << "Connection type is SINGLE, and fd = " << _current_call.sending_sock->fd();
        // TODO(gejun): Setting preferred index of single-connected socket
        // has two issues:
        //   1. race conditions. If a set perferred_index is overwritten by
        //      another thread, the response back has to check protocols one
        //      by one. This is a performance issue, correctness is unaffected.
        //   2. thrashing between different protocols. Also a performance issue.
        _current_call.sending_sock->set_preferred_index(_preferred_index);
    } else {
        int rc = 0;
        if (_connection_type == CONNECTION_TYPE_POOLED) {
            LOG(INFO) << "Connection type is POOLED" ;
            rc = tmp_sock->GetPooledSocket(&_current_call.sending_sock);
        } else if (_connection_type == CONNECTION_TYPE_SHORT) {
            LOG(INFO) << "Connection type is SHORT" ;
            rc = tmp_sock->GetShortSocket(&_current_call.sending_sock);
        } else {
            tmp_sock.reset();
            SetFailed(EINVAL, "Invalid connection_type=%d", (int)_connection_type);
            return HandleSendFailed();
        }
        if (rc) {
            tmp_sock.reset();
            SetFailed(rc, "Fail to get %s connection",
                      ConnectionTypeToString(_connection_type));
            return HandleSendFailed();
        }
        // Remember the preferred protocol for non-single connection. When
        // the response comes back, InputMessenger calls the right handler
        // w/o trying other protocols. This is a must for (many) protocols that
        // can't be distinguished from other protocols w/o ambiguity.
        _current_call.sending_sock->set_preferred_index(_preferred_index);
        // Set preferred_index of main_socket as well to make it easier to
        // debug and observe from /connections.
        if (tmp_sock->preferred_index() < 0) {
            tmp_sock->set_preferred_index(_preferred_index);
        }
        tmp_sock.reset();
    }
    if (_tos > 0) {
        _current_call.sending_sock->set_type_of_service(_tos);
    }

    // Handle authentication
    const Authenticator* using_auth = NULL;
    if (_auth != NULL) {
        // Only one thread will be the winner and get the right to pack
        // authentication information, others wait until the request
        // is sent.
        int auth_error = 0;
        if (_current_call.sending_sock->FightAuthentication(&auth_error) == 0) {
            using_auth = _auth;
        } else if (auth_error != 0) {
            SetFailed(auth_error, "Fail to authenticate, %s",
                      berror(auth_error));
            return HandleSendFailed();
        }
    }
    // Make request
    sgxbutil::IOBuf packet;
    SocketMessage* user_packet = NULL;
    _pack_request(&packet, &user_packet, cid.value, _method, this,
                  _request_buf, using_auth);
    // VLOG(79) << "Func: " << __FUNCTION__ << " RPC call method = " 
    //     << this->_method->name() << " package size = " << packet.size();
    // TODO: PackRequest may accept SocketMessagePtr<>?
    SocketMessagePtr<> user_packet_guard(user_packet);
    if (FailedInline()) {
        // controller should already be SetFailed.
        if (using_auth) {
            // Don't forget to signal waiters on authentication
            _current_call.sending_sock->SetAuthentication(ErrorCode());
        }
        return HandleSendFailed();
    }

    timespec connect_abstime;
    timespec* pabstime = NULL;
    if (_connect_timeout_ms > 0) {
        if (_deadline_us >= 0) {
            connect_abstime = sgxbutil::microseconds_to_timespec(
                std::min(_connect_timeout_ms * 1000L + start_realtime_us,
                         _deadline_us));
        } else {
            connect_abstime = sgxbutil::microseconds_to_timespec(
                _connect_timeout_ms * 1000L + start_realtime_us);
        }
        pabstime = &connect_abstime;
    }
    Socket::WriteOptions wopt;
    wopt.id_wait = cid;
    wopt.abstime = pabstime;
    wopt.pipelined_count = _pipelined_count;
    wopt.with_auth = has_flag(FLAGS_REQUEST_WITH_AUTH);
    wopt.ignore_eovercrowded = has_flag(FLAGS_IGNORE_EOVERCROWDED);
    int rc;
    size_t packet_size = 0;
    if (user_packet_guard) {
        LOG(INFO) << "Write(user_packet_guard, &wopt)" ;
        rc = _current_call.sending_sock->Write(user_packet_guard, &wopt);
    } else {
        LOG(INFO) << __FUNCTION__ << " bthread-" << bthread_self() << " Write(&packet, &wopt)" ;
        packet_size = packet.size();
        rc = _current_call.sending_sock->Write(&packet, &wopt);
    }
    if (using_auth) {
        // For performance concern, we set authentication to immediately
        // after the first `Write' returns instead of waiting for server
        // to confirm the credential data
        _current_call.sending_sock->SetAuthentication(rc);
    }
    CHECK_EQ(0, bthread_id_unlock(cid));
}

void Controller::set_auth_context(const AuthContext* ctx) {
    if (_auth_context != NULL) {
        LOG(FATAL) << "Impossible! This function is supposed to be called "
                 "only once when verification succeeds in server side";
        return;
    }
    // Ownership is belong to `Socket' instead of `Controller'
    _auth_context = ctx;
}

int Controller::HandleSocketFailed(bthread_id_t id, void* data, int error_code,
                                   const std::string& error_text) {
    Controller* cntl = static_cast<Controller*>(data);
    if (!cntl->is_used_by_rpc()) {
        // Cannot destroy the call_id before RPC otherwise an async RPC
        // using the controller cannot be joined and related resources may be
        // destroyed before done->Run() running in another bthread.
        // The error set will be detected in Channel::CallMethod and fail
        // the RPC.
        cntl->SetFailed(error_code, "Cancel call_id=%" PRId64
                        " before CallMethod()", id.value);
        return bthread_id_unlock(id);
    }
    const int saved_error = cntl->ErrorCode();
    if (error_code == ERPCTIMEDOUT) {
        cntl->SetFailed(error_code, "Reached timeout=%" PRId64 "ms @%s",
                        cntl->timeout_ms(),
                        sgxbutil::endpoint2str(cntl->remote_side()).c_str());
    } else if (!error_text.empty()) {
        cntl->SetFailed(error_code, "%s", error_text.c_str());
    } else {
        cntl->SetFailed(error_code, "%s @%s", berror(error_code),
                        sgxbutil::endpoint2str(cntl->remote_side()).c_str());
    }
    CompletionInfo info = { id, false };
    cntl->OnVersionedRPCReturned(info, true, saved_error);
    return 0;
}

CallId Controller::call_id() {
    sgxbutil::atomic<uint64_t>* target =
        (sgxbutil::atomic<uint64_t>*)&_correlation_id.value;
    uint64_t loaded = target->load(sgxbutil::memory_order_relaxed);
    if (loaded) {
        const CallId id = { loaded };
        return id;
    }
    // Optimistic locking.
    CallId cid = { 0 };
    // The range of this id will be reset in Channel::CallMethod
    CHECK_EQ(0, bthread_id_create2(&cid, this, HandleSocketFailed));
    if (!target->compare_exchange_strong(loaded, cid.value,
                                         sgxbutil::memory_order_relaxed)) {
        bthread_id_cancel(cid);
        cid.value = loaded;
    }
    return cid;
}

void Controller::SaveClientSettings(ClientSettings* s) const {
    s->timeout_ms = _timeout_ms;
    s->max_retry = _max_retry;
    s->tos = _tos;
    s->connection_type = _connection_type;
    s->request_compress_type = _request_compress_type;
    s->log_id = _log_id;
    s->has_request_code = has_request_code();
    s->request_code = _request_code;
}

void Controller::ApplyClientSettings(const ClientSettings& s) {
    set_timeout_ms(s.timeout_ms);
    set_max_retry(s.max_retry);
    set_type_of_service(s.tos);
    set_connection_type(s.connection_type);
    set_request_compress_type(s.request_compress_type);
    set_log_id(s.log_id);
    set_flag(FLAGS_REQUEST_CODE, s.has_request_code);
    _request_code = s.request_code;
}


// TODO: Need more security advices from professionals.
// TODO: Is percent encoding better?
void WebEscape(const std::string& source, std::string* output) {
    output->reserve(source.length() + 10);
    for (size_t pos = 0; pos != source.size(); ++pos) {
        switch (source[pos]) {
        case '&':  output->append("&amp;");          break;
        case '\"': output->append("&quot;");         break;
        case '\'': output->append("&apos;");         break;
        case '<':  output->append("&lt;");           break;
        case '>':  output->append("&gt;");           break;
        default:   output->push_back(source[pos]);   break;
        }
    }
}



void Controller::set_stream_creator(StreamCreator* sc) {
    if (_stream_creator) {
        LOG(FATAL) << "A StreamCreator has been set previously";
        return;
    }
    _stream_creator = sc;
}



bool Controller::is_ssl() const {
    Socket* s = _current_call.sending_sock.get();
    return s != NULL && s->is_ssl();
}

x509_st* Controller::get_peer_certificate() const {
    Socket* s = _current_call.sending_sock.get();
    return s ? s->GetPeerCertificate() : NULL;
}

int Controller::GetSockOption(int level, int optname, void* optval, socklen_t* optlen) {
    Socket* s = _current_call.sending_sock.get();
    if (s) {
        return getsockopt(s->fd(), level, optname, optval, optlen);
    } else {
        errno = EBADF;
        return -1;
    }
}

typedef sighandler_t SignalHandler;

static volatile bool s_signal_quit = false;
static SignalHandler s_prev_sigint_handler = NULL;
static SignalHandler s_prev_sigterm_handler = NULL;

static void quit_handler(int signo) {
    s_signal_quit = true;
    if (SIGINT == signo && s_prev_sigint_handler) {
        s_prev_sigint_handler(signo);
    }
    if (SIGTERM == signo && s_prev_sigterm_handler) {
        s_prev_sigterm_handler(signo);
    }
}

static pthread_once_t register_quit_signal_once = PTHREAD_ONCE_INIT;

static void RegisterQuitSignalOrDie() {
    // Not thread-safe.
    SignalHandler prev = signal(SIGINT, quit_handler);
    if (prev != SIG_DFL &&
        prev != SIG_IGN) { // shell may install SIGINT of background jobs with SIG_IGN
        if (prev == SIG_ERR) {
            LOG(ERROR) << "Fail to register SIGINT, abort";
            abort();
        } else {
            s_prev_sigint_handler = prev;
            LOG(WARNING) << "SIGINT was installed with " << prev;
        }
    }

    if (FLAGS_graceful_quit_on_sigterm) {
        prev = signal(SIGTERM, quit_handler);
        if (prev != SIG_DFL &&
            prev != SIG_IGN) { // shell may install SIGTERM of background jobs with SIG_IGN
            if (prev == SIG_ERR) {
                LOG(ERROR) << "Fail to register SIGTERM, abort";
                abort();
            } else {
                s_prev_sigterm_handler = prev;
                LOG(WARNING) << "SIGTERM was installed with " << prev;
            }
        }
    }
}

bool IsAskedToQuit() {
#if RUN_OUTSIDE_SGX
    // LOG(ERROR) << "Func: " << __FUNCTION__ << " Run out side SGX...";
    pthread_once(&register_quit_signal_once, RegisterQuitSignalOrDie);
    return s_signal_quit;
#else
    return false;
#endif    
}

void AskToQuit() {
    raise(SIGINT);
}

class DoNothingClosure : public google::protobuf::Closure {
    void Run() { }
};
google::protobuf::Closure* DoNothing() {
    return sgxbutil::get_leaky_singleton<DoNothingClosure>();
}

} // namespace brpc
