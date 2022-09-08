#ifndef HOST_HOST_UTILS_H
#define HOST_HOST_UTILS_H

#include <pthread.h>
#include <vector>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#if RUN_OUTSIDE_SGX

void ocall_gettimeofday(timeval* time);
void ocall_clock_gettime(int time_type, timespec* time);
void ocall_get_logging_time(tm* local_time, uint64_t* nano_sec);

void ocall_pthread_timer_thread(int *rc, uint64_t *tid);
void ocall_pthread_general(int *rc, uint64_t *tid, uint64_t task_id, int mode);
void ocall_join_pthread(uint64_t tid);

void ocall_futex_wake_private(void* addr1, int nwake, int* ret , int* errnum);
void ocall_futex_wait_private(void* addr1, int expected, timespec* timeout, 
                              int* ret, int* errnum);

void ocall_create_counter(uint32_t *index);
void ocall_start_auth_session(void* nonce_buffer, int nonce_buf_size, 
    void* encrypted_salt_buffer, int salt_buf_size, 
    void* nonce_tpm_buffer, uint32_t* session_handle);

void ocall_add_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer);

void ocall_read_counter(uint32_t session_handle, uint32_t nv_handle,
    void* nonce_buffer, int nonce_buf_size,
    uint8_t* hmac_in_buffer, int hmac_size,
    uint8_t* nonce_tpm_buffer,
    uint8_t* hmac_out_buffer, 
    void* read_data, int read_data_size);

void ocall_fallocate(int fd, int offset, int byte_size);
#else
#include "readerwriterqueue/readerwriterqueue.h"
#include "working_queues/mpmc_bounded.h"
//- Shared data types between the enclave and the host
typedef struct HostEpollData{
    //- uint64_t
    uint64_t socket_id;
    //- In/Out
    uint32_t epoll_event;
    HostEpollData(uint64_t a, uint32_t b): socket_id(a), epoll_event(b){}
    HostEpollData(): socket_id(0), epoll_event(0){}
} HostEpollData;

typedef struct HostEpollControlData{
    //- uint64_t
    uint64_t socket_id;
    //- In/Out
    uint32_t epoll_event;
    //- Control type: EPOLL_CTL_MOD/ADD/DEL
    int control_event;
    //- file descriptor
    int fd;
    HostEpollControlData(uint64_t a, uint32_t b, int c, int d): 
        socket_id(a), epoll_event(b), control_event(c), fd(d) {}
    HostEpollControlData(): socket_id(0), epoll_event(0), control_event(0), fd(-1) {}
} HostEpollControlData;

typedef struct HostSocketIORequest{
    uint32_t* butex;
    bool is_read;
    int socket_fd;
    int length;
    int* ret_length;
    char* requester_buf;
    HostSocketIORequest(uint32_t* a): butex(a), is_read(true), length(0){}
    HostSocketIORequest(uint32_t* a, bool b, int c, int d, int* e, char* f): 
        butex(a), is_read(b), socket_fd(c), length(d), ret_length(e), requester_buf(f){}
    HostSocketIORequest(): butex(NULL), is_read(true){}
    // ~HostSocketIORequest(){}
} HostSocketIORequest;

typedef struct HostSocketIOResponse{
    uint32_t* butex;
    bool is_read;
    int length;
    int* ret_length;
    char* requester_buf;
    char* host_ret_buf;
    HostSocketIOResponse(uint32_t* a): butex(a){}
    HostSocketIOResponse
      (uint32_t* butex, bool read, int len, int* ret_len, char* req_buf, char* host_buf): 
      butex(butex), is_read(read), length(len), ret_length(ret_len), requester_buf(req_buf), host_ret_buf(host_buf){}
    HostSocketIOResponse(): butex(NULL){}
} HostSocketIOResponse;

#endif

void *worker(void *opt);
void *worker2(void *opt);

#endif