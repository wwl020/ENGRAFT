#ifndef SWITCHLESS_SYS_TIME_H
#define SWITCHLESS_SYS_TIME_H
#include <time.h>                            // timespec, clock_gettime
#include <sys/time.h>                        // timeval, gettimeofday
#include <stdint.h>                          // int64_t, uint64_t

void ocall_gettimeofday_interface(timeval* time);
void ocall_clock_gettime_interface(int time_type, timespec* time);
void setup_shared_time_variable();

#endif