#include <stdint.h>
#include <vector>
#include "sgxbutil/state_cont/distri_state_mgr.h"
#include "sgxbutil/state_cont/opt_distri_state_mgr.h"
#include "sgxbutil/logging.h"
#include <pthread.h>

#include "sgxbutil/string_splitter.h"
#include "braft/protobuf_file.h"
#include "sgxbutil/state_cont/state_cont_service.h"
#include <math.h>
DECLARE_string(conf);
DECLARE_int32(port);

namespace sgxbutil {
static pthread_once_t g_init_distri_state_mgr_once = PTHREAD_ONCE_INIT;
static DistributedStateManager* g_distri_state_mgr = NULL;

void InitializeGlobalDistriStateMgr() {
    // g_distri_state_mgr = new DistributedStateManager();
    g_distri_state_mgr = new OptDistriStateManager();
    g_distri_state_mgr->init();
}

DistributedStateManager* GetGlobalDistributedStateManager() {
    pthread_once(&g_init_distri_state_mgr_once, InitializeGlobalDistriStateMgr);
    return g_distri_state_mgr;
}

int DistributedStateManager::init() {
    //- Get its own IP address and port
    sgxbutil::EndPoint self_addr(sgxbutil::my_ip(), FLAGS_port);
    braft::PeerId self_peer_id_tmp(self_addr);
    self_peer_id = self_peer_id_tmp;
    LOG(INFO) << "Func: " << __FUNCTION__ << " self_peer_id = " << self_peer_id;
    //- Temple vars
    std::string peer_str;
    sgxbutil::StringPiece conf(FLAGS_conf);

    //- 1. Assign value in _counter_table
    //- 2. Add peers in peers
    //- 3. Init channels for peers
    braft::PeerId peer_null;
    for (sgxbutil::StringSplitter sp(conf.begin(), conf.end(), ','); sp; ++sp) {
        peer_str.assign(sp.field(), sp.length());
        braft::PeerId peer;
        if (peer.parse(peer_str) != 0) {
            LOG(ERROR) << "Fail to parse " << peer_str;
            return -1;
        }
        //- Init vote table
        vote_table[peer] = VoteData(1, peer_null, 0);
        //- Init log hash table
        log_store_hash_table[peer] = LogStoreHash(0, 0, "NULL", 0);

        //- Exclude self in peers
        LOG(INFO) << "Func: " << __FUNCTION__ << " peer = " << peer;
        if (peer != self_peer_id) {
            peers.insert(peer);
            brpc::Channel* channel = new brpc::Channel();
            if (channel->Init(peer.addr, &channel_opt) != 0) {
                LOG(WARNING) << "Fail to init distributed counter channel";
            }
            peers_channels[peer] = channel;
        } else {
            //- Update self_id
            self_id.assign(sp.field(), sp.length());
        }
    }
    quorum_size = (int)ceil((peers.size() + 1) / 2.0);

    //- TODO: Ask the cluster for updated states

    // _print_counter_table();
    VLOG(79) << "Func: " << __FUNCTION__ << " Initialized the distributed manager";
    return 0;
}

int DistributedStateManager::get_term_and_votedfor(int64_t* term, braft::PeerId* peer_id) {
    pthread_mutex_lock(&vote_info_self);
    *term = vote_table[self_peer_id].current_term;
    *peer_id = vote_table[self_peer_id].voted_for;
    pthread_mutex_unlock(&vote_info_self);
    return 0;
}

int DistributedStateManager::set_term_and_votedfor(const int64_t term, 
                                                const braft::PeerId& peer_id) {
    //- When `peer_id` is null, we still need two-round communication 
    //- to safely store `term` value
    // VLOG(79) << " Func: " << __FUNCTION__ << " term = " << term
        // << ", voted for " << peer_id;
    pthread_mutex_lock(&vote_info_self);
    VoteData vote_data(term, peer_id, vote_table[self_peer_id].index + 1);
    vote_table[self_peer_id].current_term = term;
    vote_table[self_peer_id].voted_for = peer_id;
    vote_table[self_peer_id].index++;

    while (round_communication(self_id, NULL, &vote_data, 1) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 1 communication failed!";
        sleep(1);
    }
    while (round_communication(self_id, NULL, &vote_data, 2) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 2 communication failed!";
        sleep(1);
    }
    pthread_mutex_unlock(&vote_info_self);
    return 0;
}

int DistributedStateManager::set_vote_info_for_others(bool confirm_mode,
                                                    std::string sender_id, 
                                                    int64_t cur_term, 
                                                    std::string voted_for, 
                                                    uint64_t index) {
    if (vote_table.find(sender_id) == vote_table.end()) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find this peer: " << sender_id;
        return -1;
    }
    if (confirm_mode) {
        // BAIDU_SCOPED_LOCK(vote_table_mutex);
        if (vote_table[sender_id].index >= index) {
            return 0;
        }
        return -1;
    }
    pthread_mutex_lock(&vote_table_mutex);
    vote_table[sender_id].voted_for = voted_for;
    vote_table[sender_id].current_term = cur_term;
    vote_table[sender_id].index = index;
    pthread_mutex_unlock(&vote_table_mutex);
    LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Successfully help " 
        << sender_id << " to set its cur_term to " << cur_term 
        << ", voted_for to " << voted_for << ", index to " << index;
    return 0;
}

int DistributedStateManager::get_log_store_hash(std::string* hash, 
                        int64_t* first_log_idx, 
                        int64_t* last_log_idx) {
    BAIDU_SCOPED_LOCK(log_hash_self);
    *hash = log_store_hash_table[self_peer_id].chained_hash;
    *first_log_idx = log_store_hash_table[self_peer_id].first_log_index;
    *last_log_idx = log_store_hash_table[self_peer_id].last_log_index;
    return 0;
}

int DistributedStateManager::set_log_store_hash(std::string hash, 
                                            int64_t first_log_idx, 
                                            int64_t last_log_idx) {
    VLOG(79) << "Func: " << __FUNCTION__ << " setting log store hash";
    BAIDU_SCOPED_LOCK(log_hash_self);
    LogStoreHash log_hash(first_log_idx, last_log_idx, 
                        hash, log_store_hash_table[self_peer_id].index + 1);
    log_store_hash_table[self_peer_id].first_log_index = first_log_idx;
    log_store_hash_table[self_peer_id].last_log_index = last_log_idx;
    log_store_hash_table[self_peer_id].chained_hash = hash;
    log_store_hash_table[self_peer_id].index++;

    while (round_communication(self_id, &log_hash, NULL, 1) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 1 communication failed!";
    }
    while (round_communication(self_id, &log_hash, NULL, 2) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 2 communication failed!";
    }
    return 0;
}

int DistributedStateManager::set_log_store_hash_for_others_pipeline(
                                            const StateStoreRequest* req) {
    LOG(ERROR) << "Func: " << __FUNCTION__ << " Not implemented!";
    return -1;
}

int DistributedStateManager::set_log_store_hash_for_others(bool confirm_mode, 
                            std::string sender_id, int64_t first_log_idx, 
                            int64_t last_log_idx, std::string log_hash, uint64_t index) {
    if (log_store_hash_table.find(sender_id) == log_store_hash_table.end()) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find this peer: " << sender_id;
        return -1;
    }
    if (confirm_mode) {
        // BAIDU_SCOPED_LOCK(log_table_mutex);
        if (log_store_hash_table[sender_id].index >= index) {
            return 0;
        }
        return -1;
    }
    BAIDU_SCOPED_LOCK(log_table_mutex);
    log_store_hash_table[sender_id].first_log_index = first_log_idx;
    log_store_hash_table[sender_id].last_log_index = last_log_idx;
    log_store_hash_table[sender_id].chained_hash = log_hash;
    log_store_hash_table[sender_id].index = index;
    LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Successfully help " 
        << sender_id << " to set its first/last_log_index to " << first_log_idx 
        << "/" << last_log_idx << ", chained_hash to " 
        << log_hash << ", index to " << index;
    return 0;
}

void DistributedStateManager::print_manager_info() {
    LOG_MACRO_STATE_CONT << " self_peer_id = " << self_peer_id;
    LOG_MACRO_STATE_CONT << " self_id = " << self_id;
    LOG_MACRO_STATE_CONT << " quorum_size = " << quorum_size;
    LOG_MACRO_STATE_CONT << " peers.size = " << peers.size();
    LOG_MACRO_STATE_CONT << " peers_channels.size = " << peers_channels.size();

    LOG_MACRO_STATE_CONT << " vote_table.size = " << vote_table.size();
    for (std::map<braft::PeerId, VoteData>::iterator it = vote_table.begin(); it != vote_table.end(); it++) {
        LOG_MACRO_STATE_CONT << "PeerID = " << it->first << ", VoteData = " 
            << it->second.to_print_string();
    }
    
    LOG_MACRO_STATE_CONT << " log_store_hash_table.size = " << log_store_hash_table.size();
    for (std::map<braft::PeerId, LogStoreHash>::iterator it = log_store_hash_table.begin(); it != log_store_hash_table.end(); it++) {
        LOG_MACRO_STATE_CONT << "PeerID = " << it->first << ", LogStoreHash = " 
            << it->second.to_print_string();
    }
}

//- Use the "semi-synchronous-call" pattern
//- https://github.com/apache/incubator-brpc/blob/master/docs/en/client.md#semi-synchronous-call
int DistributedStateManager::round_communication(std::string key_id, 
                                                LogStoreHash* log_hash,
                                                VoteData* vote_data, int round) {
    sgxbutil::Timer round_timer;
    round_timer.start();
    // for (int i = 0; i < 3000000; i++) {
    //     i = i + 1 - 1;
    // }
    bool confirm_mode = (round == 1 ? false : true);
    const int peer_cnt = peers.size();
    brpc::Controller cntls[peer_cnt];
    StateStoreRequest requests[peer_cnt];
    StateContinuityResp responses[peer_cnt];
    for (int i = 0; i < peer_cnt; i++) {
        cntls[i].set_timeout_ms(30);
    }
    if (log_hash == NULL) {
        fill_vote_requests(confirm_mode, key_id, vote_data, requests, peer_cnt);
    } else {
        fill_log_hash_requests(confirm_mode, key_id, log_hash, requests, peer_cnt);
    }

    //- Send RPC to other nodes
    LOG(INFO) << "Func: " << __FUNCTION__ << " trying to store states";
    std::map<braft::PeerId, brpc::Channel*>::iterator iter;
    int index = 0;
    for (iter = peers_channels.begin(); iter != peers_channels.end(); iter++) {
        StateContService_Stub stub(iter->second);
        stub.store_states(&cntls[index], &requests[index], 
                            &responses[index], brpc::DoNothing());
        index ++;
    }
    for (int i = 0; i < peer_cnt; i++) {
        brpc::Join(cntls[i].call_id());
    }

    int success_count = 0;
    for (int i = 0; i < peer_cnt; i++) {
        if (cntls[i].Failed()) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " fail to send StoreState RPC"
                << " to " << cntls[i].remote_side();
            braft::PeerId pid(cntls[i].remote_side());
            std::map<braft::PeerId, brpc::Channel*>::iterator it =
                 peers_channels.find(pid);
            if (it != peers_channels.end()) {
                LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " its channel_ptr = "
                    << it->second;
                it->second->Init(it->first.addr, &channel_opt);
            }
        } else {
            if (responses[i].success()) {
                if (++success_count + 1 >= quorum_size) {
                    round_timer.stop();
                    VLOG(79) << "Func: " << __FUNCTION__ << " TIME_OF round #" << round
                        << " communication = " << round_timer.m_elapsed(0.0) << " ms";
                    return 0;
                }
            } else {
                LOG(ERROR) << "Func: " << __FUNCTION__ 
                    << " The remote side fails to store states!";
            }
        }
    }
    return -1;
}

int DistributedStateManager::fill_vote_requests(bool confirm_mode, std::string key_id, 
                        VoteData* vote_data, StateStoreRequest* requests, int peer_cnt) {
    for (int i = 0; i < peer_cnt; i++) {
        requests[i].set_confirmation(confirm_mode);
        VoteInfo* vote_info = requests[i].mutable_vote_info();
        vote_info->set_sender_id(key_id);
        vote_info->set_current_term(vote_data->current_term);
        vote_info->set_voted_for(vote_data->voted_for.to_string());
        vote_info->set_vote_info_index(vote_data->index);
    }
    return 0;
}

int DistributedStateManager::fill_log_hash_requests(bool confirm_mode, 
                        std::string key_id, LogStoreHash* log_hash, 
                        StateStoreRequest* requests, int peer_cnt) {
    for (int i = 0; i < peer_cnt; i++) {
        requests[i].set_confirmation(confirm_mode);
        LogStoreInfo* log_store_info = requests[i].mutable_log_store_info();
        log_store_info->set_sender_id(key_id);
        log_store_info->set_log_store_info_index(log_hash->index);
        log_store_info->set_first_log_index(log_hash->first_log_index);
        log_store_info->set_last_log_index(log_hash->last_log_index);
        log_store_info->set_chained_hash(log_hash->chained_hash);
    }
    return 0;
}

}
