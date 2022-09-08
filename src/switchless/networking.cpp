#include "switchless/networking.h"
#include <openssl/bio.h> //- set_read_write_socket_custom
#include <sys/socket.h>
#include "bthread/bthread.h"
#include "bthread/butex.h"
#include "bthread/unstable.h"
#include "sgxbutil/third_party/working_queues/mpmc_bounded.h"
#include "sgxbutil/third_party/working_queues/socket_write_queue.h"
#include <vector>
#include "interface_t.h"
extern std::vector<void*>* shared_ptrs;
sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>* rw_req_queue;
sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>* rw_resp_queue;
sgx_mpmc_queue::socket_write_queue* w_req_queue;

int readsocket_custom_impl(int fd, char* buf, int len) {
    int ret = recv(fd, buf, len, 0);
    VLOG(0) << "Func: " << __FUNCTION__ << "read from " << fd 
        << " expect_len = " << len
        << ", read_len = " << ret;
    return ret;

    // return recv(fd, buf, len, 0);
}
int writesocket_custom_impl(int fd, const char* buf, int len) {
    // VLOG(0) << "Func: " << __FUNCTION__ << " write to " << fd << ", len = " << len;
    return write(fd, buf, len);
}

void setup_ssl_read_write_func() {
    //- Vanilla read/write function
    // set_read_write_socket_custom(readsocket_custom_impl, writesocket_custom_impl);

    // set_read_write_socket_custom(ssl_readsocket, writesocket_custom_impl);
    // set_read_write_socket_custom(ssl_readsocket_spin, writesocket_custom_impl);

    //- Used in evaluation
    set_read_write_socket_custom(ssl_readsocket_spin, ssl_writesocket);
    
    //- Remember to modify poll_socket_io_results func 
    //  when using different ssl_read_socket
    // set_read_write_socket_custom(ssl_readsocket, ssl_writesocket);
}

int ssl_readsocket(int fd, char* buf, int len) {
    uint32_t* io_butex = bthread::butex_create_checked<uint32_t>();
    *io_butex = 0;
    int ret_len = 0;
    HostSocketIORequest read_req(io_butex, true, fd, len, &ret_len, buf);
    rw_req_queue->enqueue(read_req);
    // VLOG(0) << "Func: " << __FUNCTION__ << " Waiting on " << io_butex;
    bthread::butex_wait(io_butex, 0, NULL);
    // VLOG(0) << "Func: " << __FUNCTION__ << " Waking on " << io_butex;
    bthread::butex_destroy(io_butex);
    if (ret_len == -1) {
        errno = EAGAIN;
    }
    return ret_len;
}

int ssl_readsocket_spin(int fd, char* buf, int len) {
    uint32_t* io_butex = (uint32_t*)malloc(sizeof(uint32_t));
    int ret_len = 0;
    *io_butex = 0;
    HostSocketIORequest read_req(io_butex, true, fd, len, &ret_len, buf);
    rw_req_queue->enqueue(read_req);
    while(__atomic_load_n(io_butex, __ATOMIC_RELAXED) == 0) {
        //- wait until response
    }
    free(io_butex);
    // VLOG(0) << " Func: " << __FUNCTION__ << " wakeup... fd = " << fd << ", ex_len = "
    //     << len << ", return length = " << ret_len;
    if (ret_len == -1) {
        errno = EWOULDBLOCK;
    }
    return ret_len;
}

int ssl_writesocket(int fd, const char* buf, int len) {
    w_req_queue->enqueue(fd, buf, len);
    return len;
}

void* poll_socket_io_results(void* arg) {
    // bool has_data;
    // HostSocketIOResponse resp;
    // while (true) {
    //     has_data = rw_resp_queue->dequeue(resp);
    //     if (has_data) {
    //         // VLOG(0) << "Func: " << __FUNCTION__ << " resp.len = " << resp.length;
    //         //- void* memcpy(void* dest, const void* src, std::size_t count)
    //         if (resp.length > 0) {
    //             memcpy(resp.requester_buf, resp.host_ret_buf, resp.length);
    //         }
            
    //         *resp.ret_length = resp.length;
    //         // __atomic_store_n(resp.butex, 1, __ATOMIC_RELEASE);
    //         *(resp.butex) = 1;
    //         bthread::butex_wake(resp.butex);
    //         // VLOG(0) << "Func: " << __FUNCTION__ << " Trying to wake butex = " << resp.butex << " value = " << *(resp.butex);
    //     }
    // }
    // return NULL;

    //- ssl_readsocket_spin version
    bool has_data;
    HostSocketIOResponse resp;
    while (true) {
        has_data = rw_resp_queue->dequeue(resp);
        if (has_data ) {
            //- void* memcpy(void* dest, const void* src, std::size_t count)
            if (resp.length > 0) {
                memcpy(resp.requester_buf, resp.host_ret_buf, resp.length);
            }
            *resp.ret_length = resp.length;
            __atomic_store_n(resp.butex, 1, __ATOMIC_RELAXED);
        }
    }
    return NULL;
}

HostSocketIOResponse resp;
void poll_socket_io_results_func() {
    while (rw_resp_queue->dequeue(resp)) {
        //- void* memcpy(void* dest, const void* src, std::size_t count)
        if (resp.length > 0) {
            memcpy(resp.requester_buf, resp.host_ret_buf, resp.length);
        }
        *resp.ret_length = resp.length;
        __atomic_store_n(resp.butex, 1, __ATOMIC_RELAXED);
    }
}

void test_enclave_ptr_passing() {
    sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>* req_q;
    sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>* resp_q;

    req_q = static_cast<sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>*>((*shared_ptrs)[0]);
    resp_q = static_cast<sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>*>((*shared_ptrs)[1]);
    uint32_t* a = new uint32_t;
    *a = 999;
    HostSocketIORequest A(a);
    req_q->enqueue(A);
    VLOG(0) << "Func: " << __FUNCTION__ << " a = " << a
        << ", *a = " << *a;
    HostSocketIOResponse B;        
    bool success = false;
    while (!success) {
        success = resp_q->dequeue(B);
    }
    VLOG(0) << "Func: " << __FUNCTION__ << " dequeue successfully...";
    (*B.butex)++;
    VLOG(0) << "Func: " << __FUNCTION__ << " b = " << B.butex
        << ", *b = " << *(B.butex);
}

void setup_socket_working_queues() {
    rw_req_queue = static_cast<sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>*>((*shared_ptrs)[2]);
    rw_resp_queue = static_cast<sgx_mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>*>((*shared_ptrs)[3]);
    w_req_queue = static_cast<sgx_mpmc_queue::socket_write_queue*>((*shared_ptrs)[4]);
}