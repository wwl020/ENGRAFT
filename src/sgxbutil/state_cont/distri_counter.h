#ifndef SGXBUTIL_DISTRI_COUNTER_H
#define SGXBUTIL_DISTRI_COUNTER_H
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/containers/flat_map.h"
//- TODO: Code in sgxbutil should not include code in braft/brpc
#include "braft/configuration.h"
#include "brpc/channel.h"

namespace sgxbutil {
class DistriCounter: public MonoCounterManager {
public:    
    int init() override;
    CounterID get_counter() override;
    //- There're only 2 counters in distributed counter cluster.
    //- Counter index 0 for log counter; Counter index 1 for vote counter
    int increase_counter(CounterID counter_index) override;
    CounterVal read_counter(CounterID counter_index) override;
    bool detect_rollback(CounterID counter_index, CounterVal counter_val) override;

    //- When asked to increase a counter for other nodes, call this function
    //- id format = ip:port:0:0/1 
    //- The final 0/1 is used to indicate which counter (log/vote counter) is increased
    int increase_counter_for_others(std::string id, uint64_t expected_value, bool confirm_mode) override;
    //- When asked to read counters for other nodes, call this function
    //- id format = ip:port:0
    int read_counter_for_others(std::string id, std::vector<uint64_t>& counters) override;
    
    DistriCounter() {
        _log_counter = 0;
        _vote_counter = 0;
        _channel_opt.mutable_ssl_options();
        //- TODO: Defalut timeout is 500ms, need customization
        _channel_opt.timeout_ms = -1;
    }
private:
    void _print_counter_table();
    int _round_communicate(std::string key_id, CounterID counter_index, 
                               CounterVal expect_val, int round);

    //- _self_counter_id is indeed authentication id
    std::string _self_counter_id;
    std::map<std::string, uint64_t> _counter_table;
    std::map<braft::PeerId, brpc::Channel*> _peers_channels;
    std::set<braft::PeerId> _peers;
    int _quorum_size;
    braft::PeerId _self_peer_id;
    //- Channel options for communication
    brpc::ChannelOptions _channel_opt;
    pthread_mutex_t _self_counter_mutex = PTHREAD_MUTEX_INITIALIZER;
    //- Use _self_counter_mutex to protect concurrent access to the following counters
    CounterVal _log_counter;
    CounterVal _vote_counter;
    
};
}


#endif