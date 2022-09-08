#include "host/host_utils.h"
#if RUN_OUTSIDE_SGX
extern void ecall_pthread_timer_thread(void* futex);
extern void ecall_pthread_general(uint64_t task_id);
#else 
#include "interface_u.h"
#endif

#include <iostream>
#include <syscall.h>                    // SYS_futex
#include <linux/futex.h>                // FUTEX_WAIT, FUTEX_WAKE
#include <fcntl.h>
#include <sys/stat.h>

static int pthread_cnt = 0;
#ifndef RUN_OUTSIDE_SGX
extern oe_enclave_t* enclave;
#endif

void ocall_gettimeofday_nocopy() {
    int i = 0;
}
void ocall_gettimeofday(timeval* time) {
    gettimeofday(time, NULL);
}
void ocall_gettimeofday_switch(timeval* time) {
    gettimeofday(time, NULL);
}

void ocall_clock_gettime(int time_type, timespec* time) {
    clock_gettime(time_type, time);
}

void ocall_get_logging_time(tm* local_time, uint64_t* nano_sec) {
    timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    time_t t = now.tv_sec;
    localtime_r(&t, local_time);
    *nano_sec = now.tv_nsec;
}

void ocall_free_data(void* ptr) {
    free(ptr);
}

void ocall_pthread_general(int *rc, uint64_t *tid, uint64_t task_id, int mode) {
    pthread_cnt++;
    fprintf(stderr, "%s, pth_cnt = %d\n", __FUNCTION__, pthread_cnt);
    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    if (mode == 1) {
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    } else {
        pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE);
    }
    uint64_t *opt = (uint64_t*)malloc(sizeof(uint64_t));
    *opt = task_id;
    
    *rc = pthread_create(tid, &attributes, worker2, opt);
    if (*rc != 0) {

    }
    pthread_attr_destroy(&attributes);
}

void ocall_pthread_timer_thread(int *rc, uint64_t *tid) {
    int *opt = (int*)malloc(sizeof(int));
    *opt = 1;
    *rc = pthread_create(tid, NULL, worker, opt);
}

void ocall_join_pthread(uint64_t tid) {
    std::cout << "Joining pthread, id = " << tid << std::endl;
    int ret = pthread_join(tid, NULL);
}

void ocall_futex_wait_private(void* addr1, int expected, timespec* timeout, 
                              int* ret, int* errnum) {
    *errnum = 0;
    *ret = syscall(SYS_futex, addr1, (FUTEX_WAIT | FUTEX_PRIVATE_FLAG),
                   expected, timeout, NULL, 0);
    if (*ret != 0) {
        *errnum = errno;
    }
}

void ocall_futex_wake_private(void* addr1, int nwake, int* ret , int* errnum) {
    *errnum = 0;
    *ret = syscall(SYS_futex, addr1, (FUTEX_WAKE | FUTEX_PRIVATE_FLAG),
                   nwake, NULL, NULL, 0);
    if (*ret < 0) {
        *errnum = errno;
    }
}

void *worker(void *opt) {
    std::cout << "WORKER START" << std::endl;    
    int option = *(static_cast<int*>(opt));
    free(opt);
    std::cout << "Call option = " << option << std::endl;
    switch (option) {
        case 1:
            {
                int* os_futex = (int*)malloc(sizeof(int));
            #if RUN_OUTSIDE_SGX            
                ecall_pthread_timer_thread((void*)os_futex);
            #else 
                ecall_pthread_timer_thread(enclave, (void*)os_futex);
            #endif
            }
            break;

        default:
            break;
    }
    // 一定要有返回值！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
    return nullptr;
}

void *worker2(void *opt) {
    // std::cout << "enclave = " << enclave << std::endl;
    // std::cout << "WORKER2 START" << std::endl;    
    uint64_t task_id = *(static_cast<uint64_t*>(opt));
    free(opt);
#if RUN_OUTSIDE_SGX
    ecall_pthread_general(task_id);
#else
    ecall_pthread_general(enclave, task_id);
#endif    
    return nullptr;
}

void ocall_fallocate(int fd, int offset, int byte_size) {
    // struct stat st_buf;
    // if (fstat(fd, &st_buf) != 0) {
    //     std::cout << " Fail to fstat!" << std::endl;
    //     return;
    // }
    int ret = posix_fallocate(fd, offset, byte_size);
    if (ret != 0) {
        std::cout << " Fail to fallocate, errno = " << ret << std::endl;
        return;
    }
}