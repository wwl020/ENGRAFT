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


#ifndef BRPC_SERVER_H
#define BRPC_SERVER_H

// To brpc developers: This is a header included by user, don't depend
// on internal structures, use opaque pointers instead.

#include "bthread/errno.h"        // Redefine errno
#include "google/protobuf/service.h"                 // google::protobuf::Service
#include "sgxbutil/macros.h"                            // DISALLOW_COPY_AND_ASSIGN
#include "sgxbutil/containers/doubly_buffered_data.h"   // DoublyBufferedData
// #include "bvar/bvar.h"
#include "sgxbutil/containers/case_ignored_flat_map.h"  // [CaseIgnored]FlatMap
#include "sgxbutil/ptr_container.h"
#include "brpc/controller.h"                   // brpc::Controller
#include "brpc/ssl_options.h"                  // ServerSSLOptions
#include "brpc/describable.h"                  // User often needs this
#include "brpc/builtin/tabbed.h"
#include "brpc/details/profiler_linker.h"
#include "brpc/adaptive_max_concurrency.h"
#include "brpc/http2.h"
#include "bthread/bthread.h" 

namespace brpc {

class Acceptor;
class MethodStatus;
class SimpleDataPool;
class RestfulMap;
struct SocketSSLContext;

struct ServerOptions {
    ServerOptions();  // Constructed with default options.
        
    // connections without data transmission for so many seconds will be closed
    // Default: -1 (disabled)
    int idle_timeout_sec;

    // If this option is not empty, a file named so containing Process Id
    // of the server will be created when the server is started.
    // Default: ""
    std::string pid_file;

    // Turn on authentication for all services if `auth' is not NULL.
    // Default: NULL
    const Authenticator* auth;

    // false: `auth' is not owned by server and must be valid when server is running.
    // true:  `auth' is owned by server and will be deleted when server is destructed.
    // Default: false
    bool server_owns_auth;

    // Number of pthreads that server runs on. Notice that this is just a hint,
    // you can't assume that the server uses exactly so many pthreads because
    // pthread workers are shared by all servers and channels inside a 
    // process. And there're no "io-thread" and "worker-thread" anymore,
    // brpc automatically schedules "io" and "worker" code for better
    // parallelism and less context switches.
    // If this option <= 0, number of pthread workers is not changed.
    // Default: #cpu-cores
    int num_threads;

    // Server-level max concurrency.
    // "concurrency" = "number of requests processed in parallel"
    //
    // In a traditional server, number of pthread workers also limits
    // concurrency. However brpc runs requests in bthreads which are
    // mapped to pthread workers, when a bthread context switches, it gives
    // the pthread worker to another bthread, yielding a higher concurrency
    // than number of pthreads. In some situations, higher concurrency may
    // consume more resources, to protect the server from running out of
    // resources, you may set this option.
    // If the server reaches the limitation, it responds client with ELIMIT
    // directly without calling service's callback. The client seeing ELIMIT
    // shall try another server.
    // NOTE: accesses to builtin services are not limited by this option.
    // Default: 0 (unlimited)
    int max_concurrency;

    // Default value of method-level max concurrencies,
    // Overridable by Server.MaxConcurrencyOf().
    AdaptiveMaxConcurrency method_max_concurrency;

    // Provide builtin services at this port rather than the port to Start().
    // When your server needs to be accessed from public (including traffic
    // redirected by nginx or other http front-end servers), set this port
    // to a port number that's ONLY accessible from internal network
    // so that you can check out the builtin services from this port while
    // hiding them from public. Setting this option also enables security
    // protection code which we may add constantly.
    // Update: this option affects Tabbed services as well.
    // Default: -1
    int internal_port;

    // Contain a set of builtin services to ease monitoring/debugging.
    // Read docs/cn/builtin_service.md for details.
    // DO NOT set this option to false if you don't even know what builtin
    // services are. They're very helpful for addressing runtime problems.
    // Setting to false makes -internal_port ineffective.
    // Default: true
    bool has_builtin_services;

    // Enable more secured code which protects internal information from exposure.
    bool security_mode() const { return internal_port >= 0 || !has_builtin_services; }

    // SSL related options. Refer to `ServerSSLOptions' for details
    bool has_ssl_options() const { return _ssl_options != NULL; }
    const ServerSSLOptions& ssl_options() const { return *_ssl_options.get(); }
    ServerSSLOptions* mutable_ssl_options();
    
    // [CAUTION] This option is for implementing specialized http proxies,
    // most users don't need it. Don't change this option unless you fully
    // understand the description below.
    // If this option is set, all HTTP requests to the server will be delegated
    // to this service which fully decides what to call and what to send back,
    // including accesses to builtin services and pb services.
    // The service must have a method named "default_method" and the request
    // and response must have no fields.
    //
    // Owned by Server and deleted in server's destructor
    google::protobuf::Service* http_master_service;

    // Only enable these protocols, separated by spaces.
    // All names inside must be valid, check protocols name in global.cpp
    // Default: empty (all protocols)
    std::string enabled_protocols;

    // Customize parameters of HTTP2, defined in http2.h
    H2Settings h2_settings;


private:
    // SSLOptions is large and not often used, allocate it on heap to
    // prevent ServerOptions from being bloated in most cases.
    sgxbutil::PtrContainer<ServerSSLOptions> _ssl_options;
};

// This struct is originally designed to contain basic statistics of the
// server. But bvar contains more stats and is more convenient.
struct ServerStatistics {
    size_t connection_count;
    int user_service_count;
    int builtin_service_count;
};

// Represent server's ownership of services.
enum ServiceOwnership {
    SERVER_OWNS_SERVICE,
    SERVER_DOESNT_OWN_SERVICE
};

struct ServiceOptions {
    ServiceOptions(); // constructed with default options.

    // SERVER_OWNS_SERVICE: the service will be deleted by the server.
    // SERVER_DOESNT_OWN_SERVICE: the service shall be deleted by user after
    // stopping the server.
    // Default: SERVER_DOESNT_OWN_SERVICE
    ServiceOwnership ownership;
    
    // If this option is non-empty, methods in the service will be exposed
    // on specified paths instead of default "/SERVICE/METHOD".
    // Mappings are in form of: "PATH1 => NAME1, PATH2 => NAME2 ..." where
    // PATHs are valid http paths, NAMEs are method names in the service.
    // Default: empty
    std::string restful_mappings;

    // [ Not recommended to change this option ]
    // If this flag is true, the service will convert http body to protobuf
    // when the pb schema is non-empty in http servings. The body must be
    // valid json or protobuf(wire-format) otherwise the request is rejected.
    // This option does not affect pure-http services (pb schema is empty).
    // Services that use older versions of brpc may need to turn this
    // conversion off and handle http requests by their own to keep compatible
    // with existing clients.
    // Default: true
    bool allow_http_body_to_pb;

    // decode json string to protobuf bytes using base64 decoding when this 
    // option is turned on.
    // Default: false if BAIDU_INTERNAL is defined, otherwise true
    bool pb_bytes_to_base64;
};

// Represent ports inside [min_port, max_port]
struct PortRange {
    int min_port;
    int max_port;

    PortRange(int min_port2, int max_port2)
        : min_port(min_port2), max_port(max_port2) {
    }
};

// Server dispatches requests from clients to registered services and
// and sends responses back to clients.
class Server {
public:
    enum Status {
        UNINITIALIZED = 0,
        READY = 1,
        RUNNING = 2,
        STOPPING = 3,
    };
    struct ServiceProperty {
        bool is_builtin_service;
        ServiceOwnership ownership;
        // `service' and `restful_map' are mutual exclusive, they can't be
        // both non-NULL. If `restful_map' is not NULL, the URL should be
        // further matched by it.
        google::protobuf::Service* service;
        RestfulMap* restful_map;

        bool is_user_service() const {
            return !is_builtin_service && !restful_map;
        }

        const std::string& service_name() const;
    };
    typedef sgxbutil::FlatMap<std::string, ServiceProperty> ServiceMap;

    struct MethodProperty {
        bool is_builtin_service;
        bool own_method_status;
        // Parameters which have nothing to do with management of services, but
        // will be used when the service is queried.
        struct OpaqueParams {
            bool is_tabbed;
            bool allow_http_body_to_pb;
            bool pb_bytes_to_base64;
            OpaqueParams();
        };
        OpaqueParams params;        
        // NULL if service of the method was never added as restful.
        // "@path1 @path2 ..." if the method was mapped from paths.
        std::string* http_url;
        google::protobuf::Service* service;
        const google::protobuf::MethodDescriptor* method;
        MethodStatus* status;
        AdaptiveMaxConcurrency max_concurrency;

        MethodProperty();
    };
    typedef sgxbutil::FlatMap<std::string, MethodProperty> MethodMap;

public:
    Server(ProfilerLinker = ProfilerLinker());
    ~Server();

    // A set of functions to start this server.
    // Returns 0 on success, -1 otherwise and errno is set appropriately.
    // Notes:
    // * Default options are taken if `opt' is NULL.
    // * A server can be started more than once if the server is completely
    //   stopped by Stop() and Join().
    // * port can be 0, which makes kernel to choose a port dynamically.
    
    // Start on an address in form of "0.0.0.0:8000".
    int Start(const char* ip_port_str, const ServerOptions* opt);
    int Start(const sgxbutil::EndPoint& ip_port, const ServerOptions* opt);
    // Start on IP_ANY:port.
    int Start(int port, const ServerOptions* opt);
    // Start on `ip_str' + any useable port in `range'
    int Start(const char* ip_str, PortRange range, const ServerOptions *opt);

    // NOTE: Stop() is paired with Join() to stop a server without losing
    // requests. The point of separating them is that you can Stop() multiple
    // servers before Join() them, in which case the total time to Join is
    // time of the slowest Join(). Otherwise you have to Join() them one by
    // one, in which case the total time is sum of all Join().

    // Stop accepting new connections and requests from existing connections.
    // Returns 0 on success, -1 otherwise.
    int Stop(int closewait_ms/*not used anymore*/);

    // Wait until requests in progress are done. If Stop() is not called,
    // this function NEVER return. If Stop() is called, during the waiting, 
    // this server responds new requests with `ELOGOFF' error immediately 
    // without calling any service. When clients see the error, they should 
    // try other servers.
    int Join();

    // Sleep until Ctrl-C is pressed, then stop and join this server.
    // CAUTION: Don't call signal(SIGINT, ...) in your program!
    // If signal(SIGINT, ..) is called AFTER calling this function, this 
    // function may block indefinitely.
    void RunUntilAskedToQuit();

    // Add a service. Arguments are explained in ServiceOptions above.
    // NOTE: Adding a service while server is running is forbidden.
    // Returns 0 on success, -1 otherwise.
    int AddService(google::protobuf::Service* service,
                   ServiceOwnership ownership);
    int AddService(google::protobuf::Service* service,
                   ServiceOwnership ownership,
                   const sgxbutil::StringPiece& restful_mappings);
    int AddService(google::protobuf::Service* service,
                   const ServiceOptions& options);

    // Remove a service from this server.
    // NOTE: removing a service while server is running is forbidden.
    // Returns 0 on success, -1 otherwise.
    int RemoveService(google::protobuf::Service* service);
    
    // Remove all services from this server.
    // NOTE: clearing services when server is running is forbidden.
    void ClearServices();

    // Dynamically add a new certificate into server. It can be called
    // while the server is running, but it's not thread-safe by itself.
    // Returns 0 on success, -1 otherwise.
    int AddCertificate(const CertInfo& cert);

    // Dynamically remove a former certificate from server. Can be called
    // while the server is running, but it's not thread-safe by itself.
    // Returns 0 on success, -1 otherwise.
    int RemoveCertificate(const CertInfo& cert);

    // Dynamically reset all certificates except the default one. It can be
    // called while the server is running, but it's not thread-safe by itself.
    // Returns 0 on success, -1 otherwise.
    int ResetCertificates(const std::vector<CertInfo>& certs);

    // Find a service by its ServiceDescriptor::full_name().
    // Returns the registered service pointer, NULL on not found.
    // Notice that for performance concerns, this function does not lock service
    // list internally thus races with AddService()/RemoveService().
    google::protobuf::Service*
    FindServiceByFullName(const sgxbutil::StringPiece& full_name) const;

    // Find a service by its ServiceDescriptor::name().
    // Returns the registered service pointer, NULL on not found.
    // Notice that for performance concerns, this function does not lock service
    // list internally thus races with AddService()/RemoveService().
    google::protobuf::Service*
    FindServiceByName(const sgxbutil::StringPiece& name) const;

    // Put all services registered by user into `services'
    void ListServices(std::vector<google::protobuf::Service*>* services);

    // Get statistics of this server
    void GetStat(ServerStatistics* stat) const;
    
    // Get the options passed to Start().
    const ServerOptions& options() const { return _options; }

    // Status of this server.
    Status status() const { return _status; }

    // Return true iff this server is serving requests.
    bool IsRunning() const { return status() == RUNNING; }

    // Return the first service added to this server. If a service was once
    // returned by first_service() and then removed, first_service() will
    // always be NULL.
    // This is useful for some production lines whose protocol does not 
    // contain a service name, in which case this service works as the 
    // default service.
    google::protobuf::Service* first_service() const
    { return _first_service; }

    // Set version string for this server, will be shown in /version page
    void set_version(const std::string& version) { _version = version; }
    const std::string& version() const { return _version; }

    // Return the address this server is listening
    sgxbutil::EndPoint listen_address() const { return _listen_addr; }
    
    // Last time that Start() was successfully called. 0 if Start() was
    // never called
    time_t last_start_time() const { return _last_start_time; }

    // Print the html code of tabs into `os'.
    // current_tab_name is the tab highlighted.
    void PrintTabsBody(std::ostream& os, const char* current_tab_name) const;

    // This method is already deprecated.You should NOT call it anymore.
    int ResetMaxConcurrency(int max_concurrency);

    // Get/set max_concurrency associated with a method.
    // Example:
    //    server.MaxConcurrencyOf("example.EchoService.Echo") = 10;
    // or server.MaxConcurrencyOf("example.EchoService", "Echo") = 10;
    // or server.MaxConcurrencyOf(&service, "Echo") = 10;
    // Note: These interfaces can ONLY be called before the server is started.
    // And you should NOT set the max_concurrency when you are going to choose
    // an auto concurrency limiter, eg `options.max_concurrency = "auto"`.If you
    // still called non-const version of the interface, your changes to the
    // maximum concurrency will not take effect.
    AdaptiveMaxConcurrency& MaxConcurrencyOf(const sgxbutil::StringPiece& full_method_name);
    int MaxConcurrencyOf(const sgxbutil::StringPiece& full_method_name) const;
    
    AdaptiveMaxConcurrency& MaxConcurrencyOf(const sgxbutil::StringPiece& full_service_name,
                          const sgxbutil::StringPiece& method_name);
    int MaxConcurrencyOf(const sgxbutil::StringPiece& full_service_name,
                         const sgxbutil::StringPiece& method_name) const;

    AdaptiveMaxConcurrency& MaxConcurrencyOf(google::protobuf::Service* service,
                          const sgxbutil::StringPiece& method_name);
    int MaxConcurrencyOf(google::protobuf::Service* service,
                         const sgxbutil::StringPiece& method_name) const;
private:
friend class StatusService;
friend class ProtobufsService;
friend class ConnectionsService;
friend class BadMethodService;
friend class ServerPrivateAccessor;
friend class PrometheusMetricsService;
friend class Controller;

    int AddServiceInternal(google::protobuf::Service* service,
                           bool is_builtin_service,
                           const ServiceOptions& options);

    int AddBuiltinService(google::protobuf::Service* service);

    // Remove all methods of `service' from internal structures.
    void RemoveMethodsOf(google::protobuf::Service* service);

    int AddBuiltinServices();

    // Initialize internal structure. Initializtion is
    // ensured to be called only once
    int InitializeOnce();

    // Create acceptor with handlers of protocols.
    Acceptor* BuildAcceptor();

    int StartInternal(const sgxbutil::ip_t& ip,
                      const PortRange& port_range,
                      const ServerOptions *opt);

    // Number of user added services, not counting builtin services.
    size_t service_count() const {
        return _fullname_service_map.size() -
            _builtin_service_count -
            _virtual_service_count;
    }

    // Number of builtin services.
    size_t builtin_service_count() const { return _builtin_service_count; }
    
    static void* UpdateDerivedVars(void*);   

    void GenerateVersionIfNeeded();

    const MethodProperty*
    FindMethodPropertyByFullName(const sgxbutil::StringPiece& fullname) const;

    const MethodProperty*
    FindMethodPropertyByFullName(const sgxbutil::StringPiece& full_service_name,
                                 const sgxbutil::StringPiece& method_name) const;

    const MethodProperty*
    FindMethodPropertyByNameAndIndex(const sgxbutil::StringPiece& service_name,
                                     int method_index) const;
    
    const ServiceProperty*
    FindServicePropertyByFullName(const sgxbutil::StringPiece& fullname) const;

    const ServiceProperty*
    FindServicePropertyByName(const sgxbutil::StringPiece& name) const;
    
    std::string ServerPrefix() const;

    // Mapping from hostname to corresponding SSL_CTX
    typedef sgxbutil::CaseIgnoredFlatMap<std::shared_ptr<SocketSSLContext> > CertMap;
    struct CertMaps {
        CertMap cert_map;
        CertMap wildcard_cert_map;
    };

    struct SSLContext {
        std::shared_ptr<SocketSSLContext> ctx;
        std::vector<std::string> filters;
    };
    // Mapping from [certficate + private-key] to SSLContext
    typedef sgxbutil::FlatMap<std::string, SSLContext> SSLContextMap;

    void FreeSSLContexts();

    static int SSLSwitchCTXByHostname(struct ssl_st* ssl,
                                      int* al, Server* server);

    static bool AddCertMapping(CertMaps& bg, const SSLContext& ssl_ctx);
    static bool RemoveCertMapping(CertMaps& bg, const SSLContext& ssl_ctx);
    static bool ResetCertMappings(CertMaps& bg, const SSLContextMap& ctx_map);
    static bool ClearCertMapping(CertMaps& bg);

    AdaptiveMaxConcurrency& MaxConcurrencyOf(MethodProperty*);
    int MaxConcurrencyOf(const MethodProperty*) const;
    
    DISALLOW_COPY_AND_ASSIGN(Server);
    
    Status _status;
    int _builtin_service_count;
    // number of the virtual services for mapping URL to methods.
    int _virtual_service_count;
    bool _failed_to_set_max_concurrency_of_method;
    Acceptor* _am;
    Acceptor* _internal_am;
    
    // Use method->full_name() as key
    MethodMap _method_map;

    // Use service->full_name() as key
    ServiceMap _fullname_service_map;
    
    // In order to be compatible with some RPC framework that
    // uses service->name() to designate an RPC service
    ServiceMap _service_map;

    // The only non-builtin service in _service_map, otherwise NULL.
    google::protobuf::Service* _first_service;

    // Store TabInfo of services inheriting Tabbed.
    TabInfoList* _tab_info_list;

    // Store url patterns for paths without exact service names, examples:
    //   *.flv => Method
    //   abc*  => Method
    RestfulMap* _global_restful_map;

    // Default certficate which can't be reloaded
    std::shared_ptr<SocketSSLContext> _default_ssl_ctx;

    // Reloadable SSL mappings
    sgxbutil::DoublyBufferedData<CertMaps> _reload_cert_maps;

    // Holds the memory of all SSL_CTXs
    SSLContextMap _ssl_ctx_map;
    
    ServerOptions _options;
    sgxbutil::EndPoint _listen_addr;

    std::string _version;
    time_t _last_start_time;
    bthread_t _derivative_thread;
    
    // mutable is required for `ServerPrivateAccessor' to change this bvar
    // mutable bvar::Adder<int64_t> _nerror_bvar;
    mutable int32_t BAIDU_CACHELINE_ALIGNMENT _concurrency;

};


// Test if a dummy server was already started.
bool IsDummyServerRunning();

// Start a dummy server listening at `port'. If a dummy server was already
// running, this function does nothing and fails.
// NOTE: The second parameter(ProfilerLinker) is for linking of profiling 
// functions when corresponding macros are defined, just ignore it.
// Returns 0 on success, -1 otherwise.
int StartDummyServerAt(int port, ProfilerLinker = ProfilerLinker());

} // namespace brpc

#endif  // BRPC_SERVER_H
