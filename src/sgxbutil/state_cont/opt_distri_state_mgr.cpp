#include "sgxbutil/state_cont/opt_distri_state_mgr.h"
#include <stdint.h>
#include <vector>
#include <pthread.h>
#include "sgxbutil/string_splitter.h"
#include "braft/protobuf_file.h"
#include "sgxbutil/state_cont/state_cont_service.h"
namespace sgxbutil {

int OptDistriStateManager::init() {
    DistributedStateManager::init();
    VLOG(79) << "Func: " << __FUNCTION__ << " Initialized OptDistriStateManager";
    return 0;
}

int OptDistriStateManager::_test_connection(brpc::Channel* chan, int& latency) {
    TestConnectRequest test_req;
    test_req.set_non_sense(true);
    brpc::Controller cntl;
    cntl.set_timeout_ms(3000);
    StateContService_Stub stub(chan);
    StateContinuityResp resp;
    stub.test_connectable(&cntl, &test_req, &resp, NULL);
    if (cntl.Failed() || !resp.success()) {
        return -1;
    }
    latency = cntl.latency_us();
    return 0;
}

//- Select the node with the minimal latency
int OptDistriStateManager::_update_opt_channels2() {
    if (_update_opt_count == 0) {
        //- For the first running, make sure that all nodes are online
        sleep(1);
        sleep(5);
        // sleep(5);//- 61nodes
        _update_opt_count++;
    }
    VLOG(79) << "Func: " << __FUNCTION__ ;
    _opt_peers_channels.clear();
    int count = 0;
    std::map<braft::PeerId, int> peer_latency;
    std::vector<int> latencies;

    //- We should connect all servers here firstly to establish SSL connection
    // Otherwise, remote attestation in SSL creation takes much time, which 
    // hinder the selection of minimal latency
    for (auto c: peers_channels) {
        int temp = -1;
        if (_test_connection(c.second, temp) == 0) {
            
        } else {
            c.second->Init(c.first.addr, &channel_opt);
            _test_connection(c.second, temp);
        }
        VLOG(79) << "Func: " << __FUNCTION__ << " TIME_OF test_conn = " 
            << (((temp/1000.0) > 0) ? (temp/1000.0): -1) << " ms";
        if (temp <= 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Send test conn to " << c.first.to_string() << " failed...";
        }
    }
    
    for (auto c: peers_channels) {
        int latency = 0;
        sgxbutil::Timer timer;
        if (_test_connection(c.second, latency) == 0) {
            peer_latency[c.first] = latency;
            latencies.push_back(latency);
            count++;
        } else {
            //- Init the channel, and try again
            c.second->Init(c.first.addr, &channel_opt);
            if (_test_connection(c.second, latency) == 0) {
                peer_latency[c.first] = latency;
                latencies.push_back(latency);
                count++;
            }
        }
    }
    if (count + 1 < quorum_size) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Fail to update optimal channels";
        return -1;
    }
    for (auto c: peer_latency) {
        VLOG(79) << "Func: " << __FUNCTION__ << " peer = " << c.first 
            << " latency = " << c.second << " us";
    }
    if (count != peers_channels.size()) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Some nodes are offline, may not construct the optimal set";
    }

    int opt_set_size = quorum_size - 1;
    std::sort(latencies.begin(), latencies.end());
    int latency_threashold = latencies[opt_set_size-1];
    for (auto c: latencies) {
        VLOG(79) << "Func: " << __FUNCTION__ << " Sorted latency = " << c << " us";
    }
    VLOG(79) << "Func: " << __FUNCTION__ << " latency_threashold = " 
        <<  latency_threashold << " us";
    for (auto c: peer_latency) {
        if (c.second <= (latency_threashold + 10) 
            && _opt_peers_channels.size() < (quorum_size - 1)) {
            _opt_peers_channels[c.first] = peers_channels.find(c.first)->second;
        }
    }
    if (_opt_peers_channels.size() != quorum_size - 1) {
        LOG(FATAL) << "Func: " << __FUNCTION__ << " Something wrong when constructin opt peers channels";
    }

    return 0;
}

int OptDistriStateManager::_update_opt_channels() {
    _opt_peers_channels.clear();
    int count = 0;
    VLOG(79) << "Func: " << __FUNCTION__ << " quorum_size = " << quorum_size;
    
    for (auto c: peers_channels) {
        int lat;
        if (_test_connection(c.second, lat) == 0) {
            _opt_peers_channels[c.first] = c.second;
            count++;
        } else {
            //- Init the channel, and try again
            c.second->Init(c.first.addr, &channel_opt);
            if (_test_connection(c.second, lat) == 0) {
                _opt_peers_channels[c.first] = c.second;
                count++;
            }
        }

        if (count + 1 >= quorum_size) {
            break;
        }
    }
    if (count + 1 < quorum_size) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Fail to update optimal channels";
        return -1;
    }
    return 0;
}

int OptDistriStateManager::set_log_store_hash(std::string hash, 
                                            int64_t first_log_idx, 
                                            int64_t last_log_idx) {
    // VLOG(79) << "Func: " << __FUNCTION__ ;
    LogStoreHash log_hash(first_log_idx, last_log_idx, hash, UINT64_MAX);
    //- mutex1 begin
    pthread_spin_lock(&_log_hash_index_splock);
    while (_pipeline_temp != NULL) {
        //- mutex1 end
        pthread_spin_unlock(&_log_hash_index_splock);
        //- mutex1 begin
        pthread_spin_lock(&_log_hash_index_splock);
    }
    _pipeline_temp = &log_hash;
    //- mutex1 end
    pthread_spin_unlock(&_log_hash_index_splock);

    BAIDU_SCOPED_LOCK(log_hash_self);
    bool exe_round1 = true;

    //- mutex1 begin
    pthread_spin_lock(&_log_hash_index_splock);
    _pipeline_temp = NULL;
    //- mutex1 end
    pthread_spin_unlock(&_log_hash_index_splock);

    if (log_hash.index != UINT64_MAX) {
        if (log_hash.index != log_store_hash_table[self_peer_id].index + 1) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Pipeline pre-store index error!";
            return -1;
        }
        exe_round1 = false;
    }
    log_store_hash_table[self_peer_id].first_log_index = first_log_idx;
    log_store_hash_table[self_peer_id].last_log_index = last_log_idx;
    log_store_hash_table[self_peer_id].chained_hash = hash;
    log_store_hash_table[self_peer_id].index++;
    if (exe_round1) {
        while (_round_communication(self_id, &log_hash, NULL, 1) != 0) {
            //- Loop until success
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 1 communication failed!";
            sleep(1);
            _update_opt_channels2();
        }
    }
    //- Before issuing the second RPC, check the pipeline variable
    LogStoreHash* pipeline_log_hash = NULL;
    //- mutex1 begin
    pthread_spin_lock(&_log_hash_index_splock);
    if (_pipeline_temp != NULL) {
        pipeline_log_hash = _pipeline_temp;
    }
    //- mutex1 end
    pthread_spin_unlock(&_log_hash_index_splock);

    if (pipeline_log_hash != NULL) {
        pipeline_log_hash->index = log_store_hash_table[self_peer_id].index + 1;
        while (round2_commu_pipeline(self_id, &log_hash, pipeline_log_hash) != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ 
                << " Round 2 pipelin communication failed!";
        }
    } else {
        while (_round_communication(self_id, &log_hash, NULL, 2) != 0) {
            //- Loop until success
            LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 2 communication failed!";
            sleep(2);
        }
    }
    return 0;
}

int OptDistriStateManager::set_log_store_hash_for_others_pipeline(const StateStoreRequest* req) {
    std::string sender = req->log_store_info().sender_id();
    if (log_store_hash_table.find(sender) == log_store_hash_table.end()) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find this peer: " << sender;
        return -1;
    }

    if (log_store_hash_table[sender].index < 
            req->log_store_info().log_store_info_index()) {
        return -1;
    }

    BAIDU_SCOPED_LOCK(log_table_mutex);
    log_store_hash_table[sender].first_log_index 
        = req->next_log_store_info().first_log_index();
    log_store_hash_table[sender].last_log_index 
        = req->next_log_store_info().last_log_index();
    log_store_hash_table[sender].chained_hash 
        = req->next_log_store_info().chained_hash();
    log_store_hash_table[sender].index 
        = req->next_log_store_info().log_store_info_index();
    LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Pipeline: successfully help " 
        << sender << " to set its first/last_log_index to " 
        << req->next_log_store_info().first_log_index() 
        << "/" << req->next_log_store_info().last_log_index() << ", chained_hash to " 
        << req->next_log_store_info().chained_hash() << ", index to " 
        << req->next_log_store_info().log_store_info_index();
    return 0;
}

int OptDistriStateManager::fill_next_log_hash_requests(
                        std::string key_id, LogStoreHash* log_hash, 
                        StateStoreRequest* requests, int peer_cnt) {
    for (int i = 0; i < peer_cnt; i++) {
        LogStoreInfo* log_store_info = requests[i].mutable_next_log_store_info();
        log_store_info->set_sender_id(key_id);
        log_store_info->set_log_store_info_index(log_hash->index);
        log_store_info->set_first_log_index(log_hash->first_log_index);
        log_store_info->set_last_log_index(log_hash->last_log_index);
        log_store_info->set_chained_hash(log_hash->chained_hash);
    }
    return 0;
}

int OptDistriStateManager::round2_commu_pipeline(std::string self_id, 
                            LogStoreHash* confirm_hash, LogStoreHash* pre_hash) {
    VLOG(79) << "Func: " << __FUNCTION__ << " pipeline execution";
    bool confirm_mode = true;
    const int peer_cnt = peers.size();
    brpc::Controller cntls[peer_cnt];
    StateStoreRequest requests[peer_cnt];
    StateContinuityResp responses[peer_cnt];
    for (int i = 0; i < peer_cnt; i++) {
        cntls[i].set_timeout_ms(30);
    }
    fill_log_hash_requests(confirm_mode, self_id, confirm_hash, requests, peer_cnt);
    fill_next_log_hash_requests(self_id, pre_hash, requests, peer_cnt);
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
                    // round_timer.stop();
                    // VLOG(79) << "Func: " << __FUNCTION__ << " TIME_OF round #" << round
                    //     << " communication = " << round_timer.m_elapsed(0.0) << " ms";
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

int OptDistriStateManager::_round_communication(std::string key_id, 
                        LogStoreHash* log_hash, VoteData* vote_data, int round) {
    sgxbutil::Timer round_timer;
    round_timer.start();
    bool confirm_mode = (round == 1 ? false : true);
    const int peer_cnt = _opt_peers_channels.size();
    brpc::Controller cntls[peer_cnt];
    StateStoreRequest requests[peer_cnt];
    StateContinuityResp responses[peer_cnt];
    for (int i = 0; i < peer_cnt; i++) {
        cntls[i].set_timeout_ms(3000);
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
    for (iter = _opt_peers_channels.begin(); iter != _opt_peers_channels.end(); iter++) {
        StateContService_Stub stub(iter->second);
        stub.store_states(&cntls[index], &requests[index], 
                            &responses[index], brpc::DoNothing());
                            // &responses[index], NULL);
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
            return -1;
            
        } else {
            if (responses[i].success()) {
                if (++success_count + 1 >= quorum_size) {
                    round_timer.stop();
                    // VLOG(79) << "Func: " << __FUNCTION__ << " TIME_OF round #" << round
                    //     << " communication = " << round_timer.m_elapsed(0.0) << " ms";
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

}
