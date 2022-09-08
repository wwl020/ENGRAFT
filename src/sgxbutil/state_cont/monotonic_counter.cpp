#include <stdint.h>
#include <vector>
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/logging.h"
#include "sgxbutil/state_cont/virtual_counter.h"
#include "sgxbutil/state_cont/distri_counter.h"
#include "sgxbutil/state_cont/tpm_counter.h"
#include <pthread.h>

namespace sgxbutil {
static pthread_once_t g_mono_counter_once = PTHREAD_ONCE_INIT;
static MonoCounterManager* g_mono_counter_manager = NULL;

void InitializeGlobalMonoCntManager() {
    g_mono_counter_manager = new VirtualCounter();
    // g_mono_counter_manager = new TPMCounter();
    // g_mono_counter_manager = new DistriCounter();
    g_mono_counter_manager->init();
}

MonoCounterManager& GetGlobalMonoCntManager() {
    pthread_once(&g_mono_counter_once, InitializeGlobalMonoCntManager);
    return g_mono_counter_manager[0];
}

//- When asked to increase a counter for other nodes, call this function
int MonoCounterManager::increase_counter_for_others(std::string id, uint64_t expected_value, bool confirm_mode) {
    LOG(ERROR) << " This virtual function should not be called in base class";
    return 1;
}
//- When asked to read counters for other nodes, call this function
int MonoCounterManager::read_counter_for_others(std::string id, std::vector<uint64_t>& counters) {
    LOG(ERROR) << " This virtual function should not be called in base class";
    return 1;
}

}
