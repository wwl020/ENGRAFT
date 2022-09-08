#include "sgxbutil/state_cont/distri_counter.h"
#include "sgxbutil/state_cont/counter_list.pb.h"
#include "sgxbutil/string_splitter.h"
//- TODO: Code in sgxbutil should not include code in braft
#include "braft/protobuf_file.h"
#include "sgxbutil/state_cont/state_cont_service.h"
#include <math.h>
DECLARE_string(conf);
DECLARE_int32(port);

namespace sgxbutil {
int DistriCounter::init() {
    //- Get self IP address and port
    sgxbutil::EndPoint self_addr(sgxbutil::my_ip(), FLAGS_port);
    braft::PeerId self_peer_id(self_addr);
    _self_peer_id = self_peer_id;
    LOG(INFO) << "Func: " << __FUNCTION__ << " self_peer_id = " << self_peer_id;
    //- Temple vars
    std::string peer_str;
    sgxbutil::StringPiece conf(FLAGS_conf);

    //- 1. Assign value in _counter_table
    //- 2. Add peers in _peers
    //- 3. Init channels for _peers
    for (sgxbutil::StringSplitter sp(conf.begin(), conf.end(), ','); sp; ++sp) {
        peer_str.assign(sp.field(), sp.length());
        //- "0" (counter index) means log counter
        peer_str.append(":0");
        _counter_table.insert(std::make_pair(peer_str, 0));

        peer_str.assign(sp.field(), sp.length());
        //- "1" means vote counter
        peer_str.append(":1");
        _counter_table.insert(std::make_pair(peer_str, 0));

        braft::PeerId peer;
        peer_str.assign(sp.field(), sp.length());
        if (peer.parse(peer_str) != 0) {
            LOG(ERROR) << "Fail to parse " << peer_str;
            return -1;
        }
        //- Exclude self in _peers
        LOG(INFO) << "Func: " << __FUNCTION__ << " peer = " << peer;
        if (peer != _self_peer_id) {
            _peers.insert(peer);
            brpc::Channel* channel = new brpc::Channel();
            if (channel->Init(peer.addr, &_channel_opt) != 0) {
                LOG(WARNING) << "Fail to init distributed counter channel";
            }
            _peers_channels[peer] = channel;
        } else {
            //- Update _self_counter_id
            _self_counter_id.assign(sp.field(), sp.length());
        }
    }
    _quorum_size = (int)ceil((_peers.size() + 1) / 2.0);

    //- TODO: Ask the cluster for updated counter table

    // _print_counter_table();
    LOG(INFO) << "Distrubited counter init success";
    return 0;
}

//- This should not be implemented in distributed counter
//- since the counterID is fixed when using distributed counters 
CounterID DistriCounter::get_counter() {
    LOG(ERROR) << " DistriCounter::get_counter() should not be called!";
    return 0;
}

int DistriCounter::increase_counter(CounterID counter_index) {
    CounterVal expect_val;
    std::string key_id = _self_counter_id;
    
    pthread_mutex_lock(&_self_counter_mutex);
    if (counter_index == 0) {
        expect_val = ++_log_counter;
        key_id.append(":0");
    } else {
        expect_val = ++_vote_counter;
        key_id.append(":1");
    }

    while (_round_communicate(key_id, counter_index, expect_val, 1) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 1 communication failed!";
    }
    while (_round_communicate(key_id, counter_index, expect_val, 2) != 0) {
        //- Loop until success
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Round 2 communication failed!";
    }
    
    pthread_mutex_unlock(&_self_counter_mutex);
    return 0;
}

CounterVal DistriCounter::read_counter(CounterID counter_index) {
    return counter_index == 0 ? _log_counter : _vote_counter;
}

bool DistriCounter::detect_rollback(CounterID counter_index, CounterVal counter_val) {
    return false;
}

int DistriCounter::increase_counter_for_others(std::string id, uint64_t expected_value, bool confirm_mode) {
    if (_counter_table.find(id) == _counter_table.end()) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find id in counter table!";
        return -1;
    }
    LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " id = " << id
        << " expected_value = " << expected_value << " confirm = " << confirm_mode;
    if (confirm_mode) {
        LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " Actual val = "
            << _counter_table[id] << "; expected_value = " << expected_value;
        //- If equals to expected value, return 0. Othrewise, return -1
        if (_counter_table[id] == expected_value) {return 0;}
        else {return -1;}
    }
    _counter_table[id] = expected_value;
    return 0;
}

int DistriCounter::read_counter_for_others(std::string id, std::vector<uint64_t>& counters) {
    std::string log_counter_id = id;
    log_counter_id.append(":0");
    std::string vote_counter_id = id;
    vote_counter_id.append(":1");
    counters.push_back(_counter_table[log_counter_id]);
    counters.push_back(_counter_table[vote_counter_id]);
    return 0;
}

void DistriCounter::_print_counter_table() {
    // LOG(INFO) << "Print out counter table:";
    // std::map<std::string, uint64_t>::iterator iter;
    // for (iter = _counter_table.begin(); iter != _counter_table.end(); iter++) {
    //     LOG(INFO) << "Id = " << iter->first << " Value = " << iter->second; 
    // }
    std::map<braft::PeerId, brpc::Channel*>::iterator iter2;
    for (iter2 = _peers_channels.begin(); iter2 != _peers_channels.end(); iter2++) {
        LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " peer = "
            << iter2->first << "; channel_ptr = " << iter2->second;
    }
    LOG(INFO) << "_self_counter_id = " << _self_counter_id;
    LOG(INFO) << "SIZE of _peers_channels = " << _peers_channels.size();
    LOG(INFO) << "SIZE of _peers = " << _peers.size();
    LOG(INFO) << "_quorum_size = " << _quorum_size;
}

//- Use the "semi-synchronous-call" pattern
//- https://github.com/apache/incubator-brpc/blob/master/docs/en/client.md#semi-synchronous-call
int DistriCounter::_round_communicate(std::string key_id, CounterID counter_index, 
                               CounterVal expect_val, int round) {
    // sgxbutil::Timer round_timer;
    // round_timer.start();
    const int peer_cnt = _peers.size();
    brpc::Controller cntls[peer_cnt];
    PreIncCounterReq requests[peer_cnt];
    PreIncCounterResp responses[peer_cnt];
    for (int i = 0; i < peer_cnt; i++) {
        cntls[i].set_timeout_ms(30);
        requests[i].set_id(key_id);
        requests[i].set_flag(counter_index);
        requests[i].set_expected_value(expect_val);
    }
    
    //- Send RPC to other nodes
    LOG(INFO) << "Func: " << __FUNCTION__ << " trying to increase counter";
    std::map<braft::PeerId, brpc::Channel*>::iterator iter;
    int index = 0;
    for (iter = _peers_channels.begin(); iter != _peers_channels.end(); iter++) {
        StateContService_Stub stub(iter->second);
        if (round == 1) {
            stub.pre_inc_counter(&cntls[index], &requests[index], &responses[index], brpc::DoNothing());
        } else {
            stub.confirm_inc_counter(&cntls[index], &requests[index], &responses[index], brpc::DoNothing());
        }
        index ++;
    }
    for (int i = 0; i < peer_cnt; i++) {
        brpc::Join(cntls[i].call_id());
    }

    int success_count = 0;
    for (int i = 0; i < peer_cnt; i++) {
        if (cntls[i].Failed()) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " fail to send preIncRPC"
                << " to " << cntls[i].remote_side();
            braft::PeerId pid(cntls[i].remote_side());
            std::map<braft::PeerId, brpc::Channel*>::iterator it =
                 _peers_channels.find(pid);
            if (it != _peers_channels.end()) {
                LOG_MACRO_STATE_CONT << "Func: " << __FUNCTION__ << " its channel_ptr = "
                    << it->second;
                it->second->Init(it->first.addr, &_channel_opt);
            }
        } else {
            if (responses[i].success()) {
                if (++success_count + 1 >= _quorum_size) {
                    // round_timer.stop();
                    // VLOG(79) << "Func: " << __FUNCTION__ << " TIME_OF round #" << round
                        // << " communication = " << round_timer.m_elapsed(0.0) << " ms";
                    return 0;
                }
            } else {
                LOG(ERROR) << "Func: " << __FUNCTION__ << " The remote side fails to increase counter!";
            }
        }
    }
    return -1;
}

}
