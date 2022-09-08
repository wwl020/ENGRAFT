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


#ifndef BRPC_CONTROLLER_H
#define BRPC_CONTROLLER_H

// To brpc developers: This is a header included by user, don't depend
// on internal structures, use opaque pointers instead.

#include "google/gflags/gflags.h"                     // Users often need gflags
#include "sgxbutil/intrusive_ptr.hpp"             // butil::intrusive_ptr
#include "bthread/errno.h"                     // Redefine errno
#include "sgxbutil/endpoint.h"                    // sgxbutil::EndPoint
#include "sgxbutil/iobuf.h"                       // sgxbutil::IOBuf
#include "brpc/options.pb.h"                   // CompressType
#include "brpc/errno.pb.h"                     // error code
#include "brpc/http_header.h"                  // HttpHeader
#include "brpc/authenticator.h"                // AuthContext
#include "brpc/socket_id.h"                    // SocketId
#include "brpc/stream_creator.h"               // StreamCreator
#include "brpc/protocol.h"                     // Protocol
#include "brpc/reloadable_flags.h"
#include "brpc/closure_guard.h"                // User often needs this
#include "brpc/callback.h"
#include "brpc/grpc.h"
#include <pthread.h>
#include <stdint.h>
#include <deque>
#include "bthread/bthread.h"
// EAUTH is defined in MAC
#ifndef EAUTH
#define EAUTH ERPCAUTH
#endif

extern "C" {
#ifndef USE_MESALINK
struct x509_st;
#else
#include <mesalink/openssl/x509.h>
#define x509_st X509
#endif
}

namespace brpc {
class Server;
class InputMessageBase;

// For serializing/parsing from idl services.
struct IdlNames {
    const char* request_name;  // must be string-constant
    const char* response_name; // must be string-constant
};

extern const IdlNames idl_single_req_single_res;
extern const IdlNames idl_single_req_multi_res;
extern const IdlNames idl_multi_req_single_res;
extern const IdlNames idl_multi_req_multi_res;

// The identifier to be associated with a RPC call.
typedef bthread_id_t CallId;

const int32_t UNSET_MAGIC_NUM = -123456789;

// A Controller mediates a single method call. The primary purpose of
// the controller is to provide a way to manipulate settings per RPC-call 
// and to find out about RPC-level errors.
class Controller : public google::protobuf::RpcController/*non-copyable*/ {
friend class Channel;
friend class ControllerPrivateAccessor;
friend class ServerPrivateAccessor;
    // << Flags >>
    static const uint32_t FLAGS_IGNORE_EOVERCROWDED = 1;
    static const uint32_t FLAGS_SECURITY_MODE = (1 << 1);
    static const uint32_t FLAGS_ADDED_CONCURRENCY = (1 << 2);
    // Let _done delete the correlation_id, used by combo channels to
    // make lifetime of the correlation_id more flexible.
    //- TODO: In sgx-braft, we always destroy cid in controller func, not in done.
    //- So FLAGS_DESTROY_CID_IN_DONE can be removed.
    static const uint32_t FLAGS_DESTROY_CID_IN_DONE = (1 << 7);
    static const uint32_t FLAGS_CLOSE_CONNECTION = (1 << 8);
    static const uint32_t FLAGS_LOG_ID = (1 << 9); // log_id is set
    static const uint32_t FLAGS_REQUEST_CODE = (1 << 10);
    static const uint32_t FLAGS_PB_BYTES_TO_BASE64 = (1 << 11);
    static const uint32_t FLAGS_ALLOW_DONE_TO_RUN_IN_PLACE = (1 << 12);
    static const uint32_t FLAGS_USED_BY_RPC = (1 << 13);
    static const uint32_t FLAGS_REQUEST_WITH_AUTH = (1 << 15);
    static const uint32_t FLAGS_PB_JSONIFY_EMPTY_ARRAY = (1 << 16);
    static const uint32_t FLAGS_ALWAYS_PRINT_PRIMITIVE_FIELDS = (1 << 18);
    static const uint32_t FLAGS_HEALTH_CHECK_CALL = (1 << 19);

public:
    Controller();
    ~Controller();


    // ------------------------------------------------------------------
    //                      Client-side methods
    // These calls shall be made from the client side only.  Their results
    // are undefined on the server side (may crash).
    // ------------------------------------------------------------------

    // Set/get timeout in milliseconds for the RPC call. Use
    // ChannelOptions.timeout_ms on unset.
    void set_timeout_ms(int64_t timeout_ms);
    int64_t timeout_ms() const { return _timeout_ms; }

    // Set/get maximum times of retrying. Use ChannelOptions.max_retry on unset.
    // <=0 means no retry.
    // Conditions of retrying:
    //   * The connection is broken. No retry if the connection is still on.
    //   * Not timed out.
    //   * retried_count() < max_retry().
    //   * Retry may work for the error. E.g. No retry when the request is
    //     incorrect (EREQUEST), retrying is pointless.
    void set_max_retry(int max_retry);
    int max_retry() const { return _max_retry; }

    // Get number of retries.
    int retried_count() const { return _current_call.nretry; }

    // This function has different meanings in client and server side.
    // In client side it gets latency of the RPC call. While in server side,
    // it gets queue time before server processes the RPC call.
    int64_t latency_us() const {
        if (_end_time_us == UNSET_MAGIC_NUM) {
            return sgxbutil::cpuwide_time_us() - _begin_time_us;
        }
        return _end_time_us - _begin_time_us;
    }

    // Response of the RPC call (passed to CallMethod)
    google::protobuf::Message* response() const { return _response; }

    // An identifier to send to server along with request. This is widely used
    // throughout baidu's servers to tag a searching session (a series of
    // queries following the topology of servers) with a same log_id.
    void set_log_id(uint64_t log_id);

    // Set type of service: http://en.wikipedia.org/wiki/Type_of_service
    // Current implementation has limits: If the connection is already
    // established, this setting has no effect until the connection is broken
    // and re-connected. And because of connection sharing, setting different
    // tos to a single connection is undefined.
    void set_type_of_service(short tos) { _tos = tos; }

    // Set type of connections for sending RPC.
    // Use ChannelOptions.connection_type on unset.
    void set_connection_type(ConnectionType type) { _connection_type = type; }

    // Set compression method for request.
    void set_request_compress_type(CompressType t) { _request_compress_type = t; }

    // Required by some load balancers.
    void set_request_code(uint64_t request_code) {
        add_flag(FLAGS_REQUEST_CODE);
        _request_code = request_code;
    }
    bool has_request_code() const { return has_flag(FLAGS_REQUEST_CODE); }
    uint64_t request_code() const { return _request_code; }
    
    // Mutable header of http request.
    HttpHeader& http_request() {
        if (_http_request == NULL) {
            _http_request = new HttpHeader;
        }
        return *_http_request;
    }
    bool has_http_request() const { return _http_request; }
    HttpHeader* release_http_request() {
        HttpHeader* const tmp = _http_request;
        _http_request = NULL;
        return tmp;
    }

    // User attached data or body of http request, which is wired to network
    // directly instead of being serialized into protobuf messages.
    sgxbutil::IOBuf& request_attachment() { return _request_attachment; }

    ConnectionType connection_type() const { return _connection_type; }
    // Get the called method. May-be NULL for non-pb services.
    const google::protobuf::MethodDescriptor* method() const { return _method; }

    // Attach a StreamCreator to this RPC. Notice that the ownership of sc has
    // been transferred to cntl, and sc->DestroyStreamCreator() would be called
    // only once to destroy sc.
    void set_stream_creator(StreamCreator* sc);
    
    // RPC may fail with EOVERCROWDED if the socket to write is too full
    // (limited by -socket_max_unwritten_bytes). In some scenarios, user
    // may wish to suppress the error completely. To do this, call this
    // method before doing the RPC.
    void ignore_eovercrowded() { add_flag(FLAGS_IGNORE_EOVERCROWDED); }
    
    // Set if the field of bytes in protobuf message should be encoded
    // to base64 string in HTTP request.
    void set_pb_bytes_to_base64(bool f) { set_flag(FLAGS_PB_BYTES_TO_BASE64, f); }
    bool has_pb_bytes_to_base64() const { return has_flag(FLAGS_PB_BYTES_TO_BASE64); }

    // Set if convert the repeated field that has no entry to a empty array
    // of json in HTTP response.
    void set_pb_jsonify_empty_array(bool f) { set_flag(FLAGS_PB_JSONIFY_EMPTY_ARRAY, f); }
    bool has_pb_jsonify_empty_array() const { return has_flag(FLAGS_PB_JSONIFY_EMPTY_ARRAY); }
    
    // Whether to always print primitive fields. By default proto3 primitive
    // fields with default values will be omitted in JSON output. For example, an
    // int32 field set to 0 will be omitted. Set this flag to true will override
    // the default behavior and print primitive fields regardless of their values.
    void set_always_print_primitive_fields(bool f) { set_flag(FLAGS_ALWAYS_PRINT_PRIMITIVE_FIELDS, f); }
    bool has_always_print_primitive_fields() const { return has_flag(FLAGS_ALWAYS_PRINT_PRIMITIVE_FIELDS); }
    

    // Tell RPC that done of the RPC can be run in the same thread where
    // the RPC is issued, otherwise done is always run in a different thread.
    // In current implementation, this option only affects RPC that fails
    // before sending the request.
    // This option is *rarely* needed by ordinary users. Don't set this option
    // if you don't know the consequences. Read implementions in channel.cpp
    // and controller.cpp to know more.
    void allow_done_to_run_in_place()
    { add_flag(FLAGS_ALLOW_DONE_TO_RUN_IN_PLACE); }
    // True iff above method was called.
    bool is_done_allowed_to_run_in_place() const
    { return has_flag(FLAGS_ALLOW_DONE_TO_RUN_IN_PLACE); }

    // ------------------------------------------------------------------------
    //                      Server-side methods.
    // These calls shall be made from the server side only. Their results are
    // undefined on the client side (may crash).
    // ------------------------------------------------------------------------

    // Returns true if the client canceled the RPC or the connection has broken,
    // so the server may as well give up on replying to it. The server should still
    // call the final "done" callback.
    // Note: Reaching deadline of the RPC would not affect this function, which means
    // even if deadline has been reached, this function may still return false.
    bool IsCanceled() const override;

    //- Inherit from google::protobuf::RpcController
    void NotifyOnCancel(google::protobuf::Closure* callback) override;

    // Returns the authenticated result. NULL if there is no authentication
    const AuthContext* auth_context() const { return _auth_context; }

    // Whether the underlying channel is using SSL
    bool is_ssl() const;

    // Get the peer certificate, which can be printed by ostream
    x509_st* get_peer_certificate() const;

    // Mutable header of http response.
    HttpHeader& http_response() {
        if (_http_response == NULL) {
            _http_response = new HttpHeader;
        }
        return *_http_response;
    }
    bool has_http_response() const { return _http_response; }
    HttpHeader* release_http_response() {
        HttpHeader* const tmp = _http_response;
        _http_response = NULL;
        return tmp;
    }
    
    // User attached data or body of http response, which is wired to network
    // directly instead of being serialized into protobuf messages.
    sgxbutil::IOBuf& response_attachment() { return _response_attachment; }

    // Set compression method for response.
    void set_response_compress_type(CompressType t) { _response_compress_type = t; }
    

    // Tell RPC to close the connection instead of sending back response.
    // If this controller was not SetFailed() before, ErrorCode() will be
    // set to ECLOSE.
    // NOTE: the underlying connection is not closed immediately.
    void CloseConnection(const char* reason_fmt, ...);

    // True if CloseConnection() was called.
    bool IsCloseConnection() const { return has_flag(FLAGS_CLOSE_CONNECTION); }

    // ServerOptions.security_mode is turned on, and the RPC is from
    // connections accepted from port (rather than internal_port)
    bool is_security_mode() const { return has_flag(FLAGS_SECURITY_MODE); }

    // The server running this RPC session.
    // Always NULL at client-side.
    const Server* server() const { return _server; }

    // Get the data attached to a mongo session(practically a socket).
    // MongoContext* mongo_session_data() { return _mongo_session_data.get(); }
    
    // -------------------------------------------------------------------
    //                      Both-side methods.
    // Following methods can be called from both client and server. But they
    // may have different or opposite semantics.
    // -------------------------------------------------------------------

    // Client-side: successful or last server called. Accessible from 
    // PackXXXRequest() in protocols.
    // Server-side: returns the client sending the request
    sgxbutil::EndPoint remote_side() const { return _remote_side; }
    
    // Client-side: the local address for talking with server, undefined until
    // this RPC succeeds (because the connection may not be established 
    // before RPC).
    // Server-side: the address that clients access.
    sgxbutil::EndPoint local_side() const { return _local_side; }

    // Protocol of the request sent by client or received by server.
    ProtocolType request_protocol() const { return _request_protocol; }

    // Resets the Controller to its initial state so that it may be reused in
    // a new call.  Must NOT be called while an RPC is in progress.
    void Reset() override {
        ResetNonPods();
        ResetPods();
    }
    
    // Causes Failed() to return true on the client side.  "reason" will be
    // incorporated into the message returned by ErrorText().
    // NOTE: Change http_response().status_code() according to `error_code'
    // as well if the protocol is HTTP. If you want to overwrite the 
    // status_code, call http_response().set_status_code() after SetFailed()
    // (rather than before SetFailed)
    void SetFailed(const std::string& reason) override;
    void SetFailed(int error_code, const char* reason_fmt, ...)
        __attribute__ ((__format__ (__printf__, 3, 4)));
    
    // After a call has finished, returns true if the RPC call failed.
    // The response to Channel is undefined when Failed() is true.
    // Calling Failed() before a call has finished is undefined.
    bool Failed() const override;

    // If Failed() is true, return description of the errors.
    // NOTE: ErrorText() != berror(ErrorCode()). 
    std::string ErrorText() const override;

    // Last error code. Equals 0 iff Failed() is false.
    // If there's retry, latter code overwrites former one.
    int ErrorCode() const { return _error_code; }

    // Getters:
    bool has_log_id() const { return has_flag(FLAGS_LOG_ID); }
    uint64_t log_id() const { return _log_id; }
    CompressType request_compress_type() const { return _request_compress_type; }
    CompressType response_compress_type() const { return _response_compress_type; }
    const HttpHeader& http_request() const 
    { return _http_request != NULL ? *_http_request : DefaultHttpHeader(); }
    
    const HttpHeader& http_response() const
    { return _http_response != NULL ? *_http_response : DefaultHttpHeader(); }

    const sgxbutil::IOBuf& request_attachment() const { return _request_attachment; }
    const sgxbutil::IOBuf& response_attachment() const { return _response_attachment; }

    // The id to cancel RPC call or join response.
    CallId call_id();

    // Get/set idl names. Notice that the names must be string-constant.
    // int32_t Echo(EchoRequest req, EchoResponse res);
    //                           ^                 ^
    //                       request_name      response_name
    void set_idl_names(const IdlNames& names) { _idl_names = names; }
    IdlNames idl_names() const { return _idl_names; }

    // Get/set idl result. The type is limited to be integral.
    // int32_t Echo(EchoRequest req, EchoResponse res);
    //    ^
    //  result
    void set_idl_result(int64_t result) { _idl_result = result; }
    int64_t idl_result() const { return _idl_result; }

    // Get sock option. .e.g get vip info through ttm kernel module hook,
    int GetSockOption(int level, int optname, void* optval, socklen_t* optlen);

    // Get deadline of this RPC (since the Epoch in microseconds).
    // -1 means no deadline.
    int64_t deadline_us() const { return _deadline_us; }

private:
    struct CompletionInfo {
        CallId id;           // call_id of the corresponding request
        bool responded;      // triggered by a response rather than other errors
    };

    // Call this method when receiving response/failure. If RPC failed,
    // it will try to retry this RPC. Otherwise, it calls user `done'
    // if it exists and destroys the correlation_id. Note that
    // the correlation_id MUST have been locked before this call.
    // Parameter `new_bthread':
    // false - Run this function in the current bthread/pthread. Note that
    //         it could last for a long time or even block the caller (as
    //         it contains user's `done')
    // true  - Creates a new bthread to run this function and returns to
    //         the caller immediately
    // Parameter `id':
    //         It will be used to checked against `_correlation_id' and
    //         `_current_call.nretry'. If not matched, nothing will happen,
    //         which means this event has been processed before
    // Parameter `saved_error':
    //         If the above check failed, `_error_code' will be reverted to this
    //- TODO: DEAL WITH CONTROLLER MUTEX, 其实这里'versioned'已经名不符实了，因为sgx-braft没有versioned RPC，一次RPC只有一次发送和回复（没有重试等策略），但先保留这个名字，以后改成OnRPCRetuened
    void OnVersionedRPCReturned(const CompletionInfo&,
                                bool new_bthread, int saved_error);

    static void* RunEndRPC(void* arg);
    void EndRPC(const CompletionInfo&);

    
    static int HandleSocketFailed(bthread_id_t, void* data, int error_code,
                                  const std::string& error_text);

    void HandleSendFailed();

    void set_auth_context(const AuthContext* ctx);

    // MongoContext is created by ParseMongoRequest when the first msg comes
    // over a socket, then stored in MongoContextMessage of the socket. cntl
    // gets a shared reference of the data in PocessMongoRequest. When socket
    // is recycled, the container, AKA MongoContextMessage is destroyed, which
    // has no infuluence on the cntl(s) who already gets the shared reference
    // of the MongoContext. The MongoContext will not be recycled until both
    // the container(MongoContextMessage) and all related cntl(s) are recycled.
    // void set_mongo_session_data(MongoContext* data);

    // Reset POD/non-POD fields.
    void ResetPods();
    void ResetNonPods();

    void StartCancel() override;

    // Using fixed start_realtime_us (microseconds since the Epoch) gives
    // more accurate deadline.
    void IssueRPC(int64_t start_realtime_us);

    struct ClientSettings {
        int32_t timeout_ms;
        int max_retry;                      
        int32_t tos;
        ConnectionType connection_type;         
        CompressType request_compress_type;
        uint64_t log_id;
        bool has_request_code;
        int64_t request_code;
    };

    void SaveClientSettings(ClientSettings*) const;
    void ApplyClientSettings(const ClientSettings&);
 
    bool FailedInline() const { return _error_code; }

    CallId get_id(int nretry) const {
        // CallId id = { _correlation_id + nretry + 1 };        
        // return id;

        //- We don;t use retry policy in sgx-braft
        return _correlation_id;
    }

    // Tell RPC that this particular call is used to do health check.
    bool is_health_check_call() const { return has_flag(FLAGS_HEALTH_CHECK_CALL); }

public:
    CallId current_id() const {
        // CallId id = { _correlation_id.value + _current_call.nretry + 1 };
        // return id;
        //- We don;t use retry policy in sgx-braft
        return _correlation_id;
    }
private:
    
    // Append server information to `_error_text'
    void AppendServerIdentiy();

    // Contexts for tracking and ending a sent request.
    // One RPC to a channel may send several requests due to retrying.
    struct Call {
        Call() { Reset(); }
        Call(Call*); //move semantics
        ~Call();
        void Reset();
        void OnComplete(Controller* c, int error_code, bool responded, bool end_of_rpc);

        int nretry;                     // sent in nretry-th retry.
        bool touched_by_stream_creator; 
        SocketId peer_id;               // main server id
        int64_t begin_time_us;          // sent real time.
        // The actual `Socket' for sending RPC. It's socket id will be
        // exactly the same as `peer_id' if `_connection_type' is
        // CONNECTION_TYPE_SINGLE. Otherwise, it may be a temporary
        // socket fetched from socket pool
        SocketUniquePtr sending_sock;
        StreamUserData* stream_user_data;
    };


    bool SingleServer() const { return _single_server_id != INVALID_SOCKET_ID; }

    void OnRPCBegin(int64_t begin_time_us) {
        LOG(INFO) << __FUNCTION__ << " pthread-" << pthread_self();
        _begin_time_us = begin_time_us;
        // make latency_us() return 0 when RPC is not over
        _end_time_us = begin_time_us;
    }

    void OnRPCEnd(int64_t end_time_us) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Call ID = " << _correlation_id;
        _end_time_us = end_time_us;
    }

    // Utilities for manipulating _flags
    inline void add_flag(uint32_t f) { _flags |= f; }
    inline void clear_flag(uint32_t f) { _flags &= ~f; }
    inline void set_flag(uint32_t f, bool t)
    { return t ? add_flag(f) : clear_flag(f); }
    inline bool has_flag(uint32_t f) const { return _flags & f; }

    void set_used_by_rpc() { add_flag(FLAGS_USED_BY_RPC); }
    bool is_used_by_rpc() const { return has_flag(FLAGS_USED_BY_RPC); }

    std::string& protocol_param() { return _thrift_method_name; }
    const std::string& protocol_param() const { return _thrift_method_name; }

private:
    // NOTE: align and group fields to make Controller as compact as possible.

    uint32_t _flags; // all boolean fields inside Controller
    int32_t _error_code;
    std::string _error_text;
    sgxbutil::EndPoint _remote_side;
    sgxbutil::EndPoint _local_side;
    
    const Server* _server;
    const AuthContext* _auth_context;        // Authentication result

    ProtocolType _request_protocol;
    // Some of them are copied from `Channel' which might be destroyed
    // after CallMethod.
    //- TODO: _max_retry should be removed later.
    int _max_retry;
    // Synchronization object for one RPC call. It remains unchanged even 
    // when retry happens. Synchronous RPC will wait on this id.
    CallId _correlation_id;

    ConnectionType _connection_type;

    // Used by ParallelChannel
    int _fail_limit;
    
    uint32_t _pipelined_count;

    // [Timeout related]
    int32_t _timeout_ms;
    int32_t _connect_timeout_ms;
    // Deadline of this RPC (since the Epoch in microseconds).
    int64_t _deadline_us;
    // Timer registered to trigger RPC timeout event
    bthread_timer_t _timeout_id;

    // Begin/End time of a single RPC call (since Epoch in microseconds)
    int64_t _begin_time_us;
    int64_t _end_time_us;
    short _tos;    // Type of service.
    // The index of parse function which `InputMessenger' will use
    int _preferred_index;
    CompressType _request_compress_type;
    CompressType _response_compress_type;
    uint64_t _log_id;
    google::protobuf::Message* _response;
    google::protobuf::Closure* _done;
    uint64_t _request_code;
    SocketId _single_server_id;

    // for passing parameters to created bthread, don't modify it otherwhere.
    CompletionInfo _tmp_completion_info;
    
    Call _current_call;
    
    StreamCreator* _stream_creator;

    // Fields will be used when making requests
    Protocol::PackRequest _pack_request;
    const google::protobuf::MethodDescriptor* _method;
    const Authenticator* _auth;
    sgxbutil::IOBuf _request_buf;
    IdlNames _idl_names;
    int64_t _idl_result;

    HttpHeader* _http_request;
    HttpHeader* _http_response;

    // Fields with large size but low access frequency 
    sgxbutil::IOBuf _request_attachment;
    sgxbutil::IOBuf _response_attachment;

    // Thrift method name, only used when thrift protocol enabled
    std::string _thrift_method_name;
};

// Advises the RPC system that the caller desires that the RPC call be
// canceled. If the call is canceled, the "done" callback will still be
// called and the Controller will indicate that the call failed at that
// time.
void StartCancel(CallId id);

// Suspend until the RPC finishes.
void Join(CallId id);

// Get a global closure for doing nothing. Used in semi-synchronous
// RPC calls. Example:
//   stub1.method1(&cntl1, &request1, &response1, brpc::DoNothing());
//   stub2.method2(&cntl2, &request2, &response2, brpc::DoNothing());
//   ...
//   brpc::Join(cntl1.call_id());
//   brpc::Join(cntl2.call_id());
google::protobuf::Closure* DoNothing();

// Convert non-web symbols to web equivalence.
void WebEscape(const std::string& source, std::string* output);

// True if Ctrl-C is ever pressed.
bool IsAskedToQuit();

// Send Ctrl-C to current process.
void AskToQuit();

} // namespace brpc


#endif  // BRPC_CONTROLLER_H
