#include "sgxbutil/state_cont/virtual_counter.h"
#include "sgxbutil/state_cont/counter_list.pb.h"
//- TODO: Code in sgxbutil should not include code in braft
#include "braft/protobuf_file.h"

namespace sgxbutil {
int VirtualCounter::init() {
    if (_persist_counters) {
        return 0;
    }
    std::string path("./counter.tmp");
    braft::ProtoBufFile pb_file(path);
    CounterList counter_list;
    if (pb_file.load(&counter_list) != 0) {
        PLOG(ERROR) << "Fail to load counter list from " << path;
        return -1;
    }
    for (int i = 0; i < counter_list.counters_size(); i++) {
        MonotonicCounter mc = counter_list.counters(i);
        counters.push_back(mc);
    }
    return 0;
}

CounterID VirtualCounter::get_counter() {
    if(!_persist_counters) {
        return 100;
    }
    pthread_mutex_lock(&counters_mutex);
    CounterID id = counters.size();
    MonotonicCounter mc;
    mc.set_index(id);
    mc.set_value(0);
    counters.push_back(mc);
    pthread_mutex_unlock(&counters_mutex);
    persist_data();    
    return id;
}

int VirtualCounter::increase_counter(CounterID counter_index) {
    if (!_persist_counters) {
        return 0;
    }
    pthread_mutex_lock(&counters_mutex);
    counters[counter_index].set_value(counters[counter_index].value() + 1);
    pthread_mutex_unlock(&counters_mutex);
    persist_data();
    return 0;
}

CounterVal VirtualCounter::read_counter(CounterID counter_index) {
    if(!_persist_counters) {
        return 100;
    }
    return counters[counter_index].value();
}

bool VirtualCounter::detect_rollback(CounterID counter_index, CounterVal counter_val) {
    if (!_persist_counters) {
        return false;
    }
    return !(counters[counter_index].value() == counter_val);
}

int VirtualCounter::persist_data() {
    if (!_persist_counters) {
        return 0;
    }
    pthread_mutex_lock(&counters_mutex);
    std::string path("./counter.tmp");
    braft::ProtoBufFile pb_file(path);
    CounterList counter_list;
    for (MonotonicCounter tmp:counters) {
        MonotonicCounter* mc = counter_list.add_counters();
        mc->set_index(tmp.index());
        mc->set_value(tmp.value());
    }
    pthread_mutex_unlock(&counters_mutex);
    return pb_file.save(&counter_list, true);
}


}
