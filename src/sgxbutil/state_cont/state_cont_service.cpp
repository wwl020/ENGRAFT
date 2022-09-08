#include "sgxbutil/state_cont/state_cont_service.h"
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/state_cont/distri_state_mgr.h"
#include "sgxbutil/logging.h"
#include "brpc/server.h"

namespace sgxbutil {
    StateContServiceImpl::~StateContServiceImpl() {
        //- No things happen now
    }

    void StateContServiceImpl::pre_inc_counter(google::protobuf::RpcController* cntl_base,
                              const PreIncCounterReq* request,
                              PreIncCounterResp* response,
                              google::protobuf::Closure* done) {
        // _print_pre_inc_request(request);
        brpc::ClosureGuard done_guard(done);
        brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);
        int ret = GetGlobalMonoCntManager().increase_counter_for_others(request->id(), request->expected_value(), 0);
        response->set_success(ret == 0 ? true : false);
    }
    
    void StateContServiceImpl::confirm_inc_counter(
            google::protobuf::RpcController* cntl_base, 
            const PreIncCounterReq* request,
            PreIncCounterResp* response,
            google::protobuf::Closure* done) {
        brpc::ClosureGuard done_guard(done);
        brpc::Controller* cntl = static_cast<brpc::Controller*>(cntl_base);
        int ret = GetGlobalMonoCntManager().increase_counter_for_others(request->id(), request->expected_value(), 1);
        response->set_success(ret == 0 ? true : false);
    }

    void StateContServiceImpl::_print_pre_inc_request(const PreIncCounterReq* request) {
        LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Req::id = " << request->id();
        LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Req::ex_val = " 
            << request->expected_value();
        LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Req::flag = " << request->flag();
    }

    void StateContServiceImpl::store_states(
                            google::protobuf::RpcController* controller,
                            const StateStoreRequest* request,
                            StateContinuityResp* response,
                            google::protobuf::Closure* done) {
        brpc::ClosureGuard done_guard(done);
        int ret = -1;
        //- Pipeline mode
        if (request->has_with_next_log_hash()) {
            if (request->with_next_log_hash() != true ||
                request->has_next_log_store_info() != true ||
                request->has_log_store_info() != true) {
                LOG(ERROR) << "Func: " << __FUNCTION__ << " with_next_log_hash error!";
                response->set_success(false);
                return;
            }
            ret = GetGlobalDistributedStateManager()->set_log_store_hash_for_others_pipeline(request);
            response->set_success(ret == 0 ? true : false);
            return;
        }

        //- Normal mode
        if (request->has_vote_info()) {
            ret = GetGlobalDistributedStateManager()->set_vote_info_for_others(
                    request->confirmation(), 
                    request->vote_info().sender_id(), 
                    request->vote_info().current_term(), 
                    request->vote_info().voted_for(), 
                    request->vote_info().vote_info_index());
            response->set_success(ret == 0 ? true : false);
        } else if (request->has_log_store_info()) {
            ret = GetGlobalDistributedStateManager()->set_log_store_hash_for_others(
                    request->confirmation(),
                    request->log_store_info().sender_id(),
                    request->log_store_info().first_log_index(),
                    request->log_store_info().last_log_index(),
                    request->log_store_info().chained_hash(),
                    request->log_store_info().log_store_info_index());
            response->set_success(ret == 0 ? true : false);
        } else {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " No StateStoreRequest data";
            response->set_success(false);
        }
    }

    void StateContServiceImpl::test_connectable(
                              google::protobuf::RpcController* controller,
                              const TestConnectRequest* request,
                              StateContinuityResp* response,
                              google::protobuf::Closure* done) {
        brpc::ClosureGuard done_guard(done);
        response->set_success(true);
    }

}