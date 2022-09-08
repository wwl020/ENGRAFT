#ifndef SGXBUTIL_MONOTONIC_COUNTER_H
#define SGXBUTIL_MONOTONIC_COUNTER_H
#include <stdint.h>
#include "sgxbutil/state_cont/counter_list.pb.h"
#include "sgxbutil/logging.h"
#include "sgxbutil/third_party/tss2/tss2_tpm2_types.h"

namespace sgxbutil {
typedef int32_t CounterID;
typedef uint64_t CounterVal;

class MonoCounterManager {
public:    
    //- Counter initialization
    virtual int init() = 0;
    //- Get a new counter
    virtual CounterID get_counter() = 0;
    //- Success: return 0, return 1 otherwise
    virtual int increase_counter(CounterID counter_index) = 0;
    virtual CounterVal read_counter(CounterID counter_index) = 0;
    //- If rollback is happened, return true, and return false otherwise
    virtual bool detect_rollback(CounterID counter_index, CounterVal counter_val) = 0;

    //- The following function should be implemented in distributed counter class
    //- When asked to increase a counter for other nodes, call this function
    virtual int increase_counter_for_others(std::string id, uint64_t expected_value, bool confirm_mode);
    //- When asked to read counters for other nodes, call this function
    virtual int read_counter_for_others(std::string id, std::vector<uint64_t>& counters);
};

MonoCounterManager& GetGlobalMonoCntManager();

}

#endif //SGXBUTIL_MONOTONIC_COUNTER_H