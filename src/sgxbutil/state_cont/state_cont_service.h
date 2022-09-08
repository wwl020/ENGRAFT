#ifndef SGXBUTIL_STATE_CONT_SERVICE_H
#define SGXBUTIL_STATE_CONT_SERVICE_H
#include "sgxbutil/state_cont/counter_rpc.pb.h"
#include "sgxbutil/endpoint.h"
// #define LOG_MACRO_STATE_CONT VLOG(79) 
#define LOG_MACRO_STATE_CONT LOG(INFO) 
namespace sgxbutil {
class StateContServiceImpl : public StateContService {
public:
    explicit StateContServiceImpl(sgxbutil::EndPoint addr)
        : _addr(addr) {}
    ~StateContServiceImpl();

    void pre_inc_counter(google::protobuf::RpcController* controller,
                              const PreIncCounterReq* request,
                              PreIncCounterResp* response,
                              google::protobuf::Closure* done);
    
    void confirm_inc_counter(google::protobuf::RpcController* controller,
                              const PreIncCounterReq* request,
                              PreIncCounterResp* response,
                              google::protobuf::Closure* done);

    void store_states(google::protobuf::RpcController* controller,
                              const StateStoreRequest* request,
                              StateContinuityResp* response,
                              google::protobuf::Closure* done);

    // void retrieve_states(google::protobuf::RpcController* controller,
    //                           const StateStoreRequest* request,
    //                           StateContinuityResp* response,
    //                           google::protobuf::Closure* done);
    void test_connectable(google::protobuf::RpcController* controller,
                              const TestConnectRequest* request,
                              StateContinuityResp* response,
                              google::protobuf::Closure* done);
private:
    sgxbutil::EndPoint _addr;
    void _print_pre_inc_request(const PreIncCounterReq* request);
};

}

#endif //SGXBUTIL_STATE_CONT_SERVICE_H