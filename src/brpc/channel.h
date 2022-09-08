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


#ifndef BRPC_CHANNEL_H
#define BRPC_CHANNEL_H

// To brpc developers: This is a header included by user, don't depend
// on internal structures, use opaque pointers instead.

#include <ostream>                          // std::ostream
#include "bthread/errno.h"                  // Redefine errno
#include "sgxbutil/intrusive_ptr.hpp"          // butil::intrusive_ptr
#include "sgxbutil/ptr_container.h"
#include "brpc/ssl_options.h"               // ChannelSSLOptions
#include "brpc/channel_base.h"              // ChannelBase
#include "brpc/adaptive_protocol_type.h"    // AdaptiveProtocolType
#include "brpc/adaptive_connection_type.h"  // AdaptiveConnectionType
#include "brpc/socket_id.h"                 // SocketId
#include "brpc/controller.h"                // brpc::Controller
#include "brpc/details/profiler_linker.h"

namespace brpc {

struct ChannelOptions {
    // Constructed with default options.
    ChannelOptions();

    // Issue error when a connection is not established after so many
    // milliseconds. -1 means wait indefinitely.
    // Default: 200 (milliseconds)
    // Maximum: 0x7fffffff (roughly 30 days)
    int32_t connect_timeout_ms;
    
    // Max duration of RPC over this Channel. -1 means wait indefinitely.
    // Overridable by Controller.set_timeout_ms().
    // Default: 500 (milliseconds)
    // Maximum: 0x7fffffff (roughly 30 days)
    int32_t timeout_ms;

    // Retry limit for RPC over this Channel. <=0 means no retry.
    // Overridable by Controller.set_max_retry().
    // Default: 3
    // Maximum: INT_MAX
    int max_retry;

    // Serialization protocol, defined in src/brpc/options.proto
    // NOTE: You can assign name of the protocol to this field as well, for
    // Example: options.protocol = "baidu_std";
    AdaptiveProtocolType protocol;

    // Type of connection to server. If unset, use the default connection type
    // of the protocol.
    // NOTE: You can assign name of the type to this field as well, for
    // Example: options.connection_type = "single";
    // Possible values: "single", "pooled", "short".
    AdaptiveConnectionType connection_type;

    // Channel.Init() succeeds even if there's no server in the NamingService. 
    // E.g. the BNS directory is empty. All RPC over the channel will fail before
    // new nodes being added to the NamingService.
    // Default: true (false before r32470)
    bool succeed_without_server;
    // Print a log when above situation happens.
    // Default: true.
    bool log_succeed_without_server;

    // SSL related options. Refer to `ChannelSSLOptions' for details
    bool has_ssl_options() const { return _ssl_options != NULL; }
    const ChannelSSLOptions& ssl_options() const { return *_ssl_options.get(); }
    ChannelSSLOptions* mutable_ssl_options();

    // Turn on authentication for this channel if `auth' is not NULL.
    // Note `auth' will not be deleted by channel and must remain valid when
    // the channel is being used.
    // Default: NULL
    const Authenticator* auth;

    // Channels with same connection_group share connections.
    // In other words, set to a different value to stop sharing connections.
    // Case-sensitive, leading and trailing spaces are ignored.
    // Default: ""
    std::string connection_group;

private:
    // SSLOptions is large and not often used, allocate it on heap to
    // prevent ChannelOptions from being bloated in most cases.
    sgxbutil::PtrContainer<ChannelSSLOptions> _ssl_options;
};

// A Channel represents a communication line to one server or multiple servers
// which can be used to call that Server's services. Servers may be running
// on another machines. Normally, you should not call a Channel directly, but
// instead construct a stub Service wrapping it.
// Example:
//   brpc::Channel channel;
//   channel.Init("bns://rdev.matrix.all", "rr", NULL/*default options*/);
//   MyService_Stub stub(&channel);
//   stub.MyMethod(&controller, &request, &response, NULL);
class Channel : public ChannelBase {
friend class Controller;
friend class SelectiveChannel;
public:
    Channel(ProfilerLinker = ProfilerLinker());
    ~Channel();

    // Connect this channel to a single server whose address is given by the
    // first parameter. Use default options if `options' is NULL.
    int Init(sgxbutil::EndPoint server_addr_and_port, const ChannelOptions* options);
    int Init(const char* server_addr_and_port, const ChannelOptions* options);
    int Init(const char* server_addr, int port, const ChannelOptions* options);

    // Call `method' of the remote service with `request' as input, and 
    // `response' as output. `controller' contains options and extra data.
    // If `done' is not NULL, this method returns after request was sent
    // and `done->Run()' will be called when the call finishes, otherwise
    // caller blocks until the call finishes.
    void CallMethod(const google::protobuf::MethodDescriptor* method,
                    google::protobuf::RpcController* controller,
                    const google::protobuf::Message* request,
                    google::protobuf::Message* response,
                    google::protobuf::Closure* done);

    // Get current options.
    const ChannelOptions& options() const { return _options; }

    void Describe(std::ostream&, const DescribeOptions&) const;


protected:
    int CheckHealth();

    // bool SingleServer() const { return _lb.get() == NULL; }
    //- Always use single server in sgx-braft
    bool SingleServer() const { return true; }

    int InitChannelOptions(const ChannelOptions* options);
    int InitSingle(const sgxbutil::EndPoint& server_addr_and_port,
                   const char* raw_server_address,
                   const ChannelOptions* options);

    sgxbutil::EndPoint _server_address;
    //- _server_id is assigned in Channel::InitSingle func, representing the Socket object used to communicate with the remote party. And this Socket object contains the file descriptor where current channel(controller) will wirte data to (cntl->issueRPC)
    SocketId _server_id;
    Protocol::SerializeRequest _serialize_request;
    Protocol::PackRequest _pack_request;
    Protocol::GetMethodName _get_method_name;

    ChannelOptions _options;
    int _preferred_index;
};

enum ChannelOwnership {
    OWNS_CHANNEL,
    DOESNT_OWN_CHANNEL
};

} // namespace brpc

#endif  // BRPC_CHANNEL_H
