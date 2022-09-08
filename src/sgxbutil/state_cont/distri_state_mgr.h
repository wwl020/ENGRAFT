#ifndef SGXBUTIL_DISTRI_STATE_MGR
#define SGXBUTIL_DISTRI_STATE_MGR
#include <stdint.h>
#include <string>
#include <map>
#include "braft/configuration.h"
#include "brpc/channel.h"
#include "sgxbutil/state_cont/counter_rpc.pb.h"

namespace sgxbutil {

class DistributedStateManager {
public:
    DistributedStateManager() {
        channel_opt.mutable_ssl_options();
        //- TODO: Defalut timeout is 500ms, need customization
        channel_opt.timeout_ms = -1;
    }

    struct VoteData {
        int64_t current_term;
        braft::PeerId voted_for;
        uint64_t index;
        VoteData() {}
        VoteData(int64_t term, braft::PeerId vote, uint64_t i): current_term(term), voted_for(vote), index(i) {}
        std::string to_print_string() {
            std::stringstream ss;
            ss << "current_term = " << current_term << ", voted_for = " << voted_for << 
                ", index = " << index;
            std::string str(ss.str());
            return str;
        }
    };
    struct LogStoreHash {
        int64_t first_log_index;
        int64_t last_log_index;
        std::string chained_hash;
        uint64_t index;
        LogStoreHash(){}
        LogStoreHash(int64_t a, int64_t b, std::string c, uint64_t d): first_log_index(a), last_log_index(b), chained_hash(c), index(d) {}
        std::string to_print_string() {
            std::stringstream ss;
            ss << "first_index = " << first_log_index << ", last_index = " 
                << last_log_index << ", hash = " << chained_hash 
                << ", index = " << index;
            std::string str(ss.str());
            return str;
        }
    };
    virtual int init();

    virtual int get_term_and_votedfor(int64_t* term, braft::PeerId* peer_id);
    virtual int set_term_and_votedfor(const int64_t term, const braft::PeerId& peer_id);

    virtual int get_log_store_hash(std::string* hash, int64_t* first_log_idx, 
                           int64_t* last_log_idx);
    virtual int set_log_store_hash(std::string hash, int64_t first_log_idx, 
                                    int64_t last_log_idx);

    virtual int set_vote_info_for_others(bool confirm_mode,
                                std::string sender_id, 
                                int64_t cur_term, 
                                std::string voted_for, 
                                uint64_t index);
    virtual int set_log_store_hash_for_others(bool confirm_mode, std::string sender_id,
                                    int64_t first_log_idx, int64_t last_log_idx,
                                    std::string log_hash, uint64_t index);

    virtual int set_log_store_hash_for_others_pipeline(const StateStoreRequest* req);
    virtual void print_manager_info();

    virtual int fill_vote_requests(bool confirm_mode, std::string key_id, 
                        VoteData* vote_data, StateStoreRequest* requests, int peer_cnt);
    virtual int fill_log_hash_requests(bool confirm_mode, std::string key_id, 
                        LogStoreHash* log_hash, StateStoreRequest* requests, 
                        int peer_cnt);                       
    virtual int round_communication(std::string key_id, LogStoreHash* log_hash,
                            VoteData* vote_data, int round);


    std::map<braft::PeerId, VoteData> vote_table;
    std::map<braft::PeerId, LogStoreHash> log_store_hash_table;

    //- For three-server cluster, peers.size() = 2
    std::map<braft::PeerId, brpc::Channel*> peers_channels;
    std::set<braft::PeerId> peers;
    
    //- For three-server cluster, quorum_size = 2
    int quorum_size;

    braft::PeerId self_peer_id;
    std::string self_id;

    //- Channel options for communication
    brpc::ChannelOptions channel_opt;
    //- Used to lock the whole vote_table/log_hash_table
    pthread_mutex_t vote_table_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t log_table_mutex = PTHREAD_MUTEX_INITIALIZER;
    //- Used to read/write its own vote info
    pthread_mutex_t vote_info_self = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t log_hash_self = PTHREAD_MUTEX_INITIALIZER;
};

DistributedStateManager* GetGlobalDistributedStateManager();

}

#endif //SGXBUTIL_DISTRI_STATE_MGR