#ifndef SGXBUTIL_VIRTUAL_COUNTER_H
#define SGXBUTIL_VIRTUAL_COUNTER_H
#include "sgxbutil/state_cont/monotonic_counter.h"

namespace sgxbutil {
class VirtualCounter: public MonoCounterManager {
public:    
    int init() override;
    CounterID get_counter() override;
    int increase_counter(CounterID counter_index) override;
    CounterVal read_counter(CounterID counter_index) override;
    bool detect_rollback(CounterID counter_index, CounterVal counter_val) override;
    
    VirtualCounter() :_persist_counters(false){}
    VirtualCounter(bool persistence) :_persist_counters(persistence){}
private:
    pthread_mutex_t counters_mutex = PTHREAD_MUTEX_INITIALIZER;
    std::vector<MonotonicCounter> counters;   
    int persist_data();
    bool _persist_counters; 
};
}


#endif