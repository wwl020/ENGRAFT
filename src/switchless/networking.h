#ifndef SWITCHLESS_NETWORKING_H
#define SWITCHLESS_NETWORKING_H
#include <stdint.h>

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

void setup_ssl_read_write_func();
int ssl_readsocket(int fd, char* buf, int len);
int ssl_readsocket_spin(int fd, char* buf, int len);
int ssl_writesocket(int fd, const char* buf, int len);
void test_enclave_ptr_passing();

void* poll_socket_io_results(void* arg);
//- This is called by HostEventDispatcher thread
void poll_socket_io_results_func();

void setup_socket_working_queues();

#endif