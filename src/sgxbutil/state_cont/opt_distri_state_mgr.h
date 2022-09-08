#ifndef SGXBUTIL_OPT_DISTRI_STATE_MGR
#define SGXBUTIL_OPT_DISTRI_STATE_MGR
#include "sgxbutil/state_cont/distri_state_mgr.h"
#include "sgxbutil/logging.h"
namespace sgxbutil {
class OptDistriStateManager: public DistributedStateManager {
public:
    OptDistriStateManager() {
        pthread_spin_init(&_log_hash_index_splock, PTHREAD_PROCESS_PRIVATE);
        channel_opt.mutable_ssl_options();
        //- TODO: Defalut timeout is 500ms, need customization
        channel_opt.timeout_ms = -1;
        _update_opt_count = 0;
        VLOG(79) << "__FUNC: " << __FUNCTION__ << " Creating OptDistriStateManager";
    }
    int set_log_store_hash(std::string hash, int64_t first_log_idx, 
                                    int64_t last_log_idx) override;
    int set_log_store_hash_for_others_pipeline(const StateStoreRequest* req) override;
    int init() override;
    int fill_next_log_hash_requests(
                        std::string key_id, LogStoreHash* log_hash, 
                        StateStoreRequest* requests, int peer_cnt);

private:
    //- For three-server cluster, opt_peers_channels.size() = 1,
    //  which is the minimal communication
    std::map<braft::PeerId, brpc::Channel*> _opt_peers_channels;
    //- Before issueing log hash pre-store request, save it in the set
    // Another thread may send this pre-store request with a confirm-store RPC
    std::set<LogStoreHash> _log_pre_store_set;
    LogStoreHash* _pipeline_temp = NULL;
    pthread_mutex_t _log_pre_set_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_spinlock_t _log_hash_index_splock;

    int _update_opt_channels();
    int _update_opt_channels2();
    int _update_opt_count;
    int _test_connection(brpc::Channel* chan, int& latency);
    int round2_commu_pipeline(std::string self_id, LogStoreHash* confirm_hash, 
                            LogStoreHash* pre_hash);
    int _round_communication(std::string key_id, LogStoreHash* log_hash,
                            VoteData* vote_data, int round);

};



}


#endif