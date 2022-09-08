#include "switchless/sys_time.h"
#include <vector>
#include "interface_t.h"
#include "sgxbutil/logging.h"
extern std::vector<void*>* shared_ptrs;
bool time_val_setup = false;
timeval* time_of_day_val = NULL;
timespec* clock_real_time_spec = NULL;
timespec* clock_mono_time_spec = NULL;
const size_t sizeof_timeval = sizeof(timeval);
const size_t sizeof_timespec = sizeof(timespec);
#define USE_SWITCHLESS_TIMING

void ocall_gettimeofday_interface(timeval* time) {
#ifndef USE_SWITCHLESS_TIMING
    ocall_gettimeofday(time);
    // VLOG(79) << "Func: " << __FUNCTION__ << " Switch gettimeofday: " 
    //     << "timeval size = " << sizeof(timeval)
    //     << ", timespec size = " << sizeof(timespec);
#else
    if (!time_val_setup) {
        ocall_gettimeofday(time);
        return;
    }
    memcpy(time, time_of_day_val, sizeof_timeval);
    // VLOG(79) << "Func: " << __FUNCTION__ << " Switchless gettimeofday";
#endif
}

void ocall_clock_gettime_interface(int time_type, timespec* time) {
#ifndef USE_SWITCHLESS_TIMING
    ocall_clock_gettime(time_type, time);
#else
    if (!time_val_setup) {
        ocall_clock_gettime(time_type, time);
        return;
    }
    if (time_type == CLOCK_MONOTONIC) {
        memcpy(time, clock_mono_time_spec, sizeof_timespec);
    } else {
        memcpy(time, clock_real_time_spec, sizeof_timespec);
    }
#endif    
}

void setup_shared_time_variable() {
    time_of_day_val = static_cast<timeval*>((*shared_ptrs)[5]);
    clock_real_time_spec = static_cast<timespec*>((*shared_ptrs)[6]);
    clock_mono_time_spec = static_cast<timespec*>((*shared_ptrs)[7]);
    time_val_setup = true;
}