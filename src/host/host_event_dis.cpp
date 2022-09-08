#ifndef RUN_OUTSIDE_SGX
#include "interface_u.h"
#include <pthread.h>
#include "host_utils.h"
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include "working_queues/mpsc_vyukov.h"
#include "working_queues/mpmc_bounded.h"
#include "working_queues/socket_write_queue.h"
#include <sched.h> //- sched_yield

extern oe_enclave_t* enclave;
extern std::vector<void *> shared_ptrs;
//- Global variables
int epoll_fd = 0;
moodycamel::ReaderWriterQueue<HostEpollData>* epoll_events_queue = NULL;
mpmc_queue::mpmc_bounded_queue_t<HostEpollControlData>* epoll_ctl_queue = NULL;
mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>* rw_req_queue = NULL;
mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>* rw_resp_queue = NULL;
mpmc_queue::socket_write_queue* w_req_queue;
timeval time_of_day_val;
timespec clock_real_time_spec;
timespec clock_mono_time_spec;

inline void do_write_event_func() {
    while(w_req_queue->dequeue()) {            
        
    }
    clock_gettime(CLOCK_MONOTONIC, &clock_mono_time_spec);
    clock_gettime(CLOCK_REALTIME, &clock_real_time_spec);
}

void *do_epoll_wait(void *arg) {
    moodycamel::ReaderWriterQueue<HostEpollData>* epoll_events_q =
       static_cast<moodycamel::ReaderWriterQueue<HostEpollData>*>(arg);
    uint64_t i = 0;
    epoll_fd = epoll_create(1024 * 1024);
    const int epoll_wait_size = 32;
    while (true) {
        // printf("%s: Beginning...\n", __FUNCTION__);
        epoll_event e[epoll_wait_size];
        const int n = epoll_wait(epoll_fd, e, epoll_wait_size, -1);
        // VLOG(80) << "Func: " << __FUNCTION__ << " Receive new message";

        if (n < 0) {
            if (EINTR == errno) {
                // We've checked _stop, no wake-up will be missed.
                continue;
            }
            // PLOG(FATAL) << "Fail to epoll_wait epfd=" << _epfd;
            break;
        }
        for (int i = 0; i < n; ++i) {
            epoll_events_q->enqueue({e[i].data.u64, e[i].events});
        }
        do_write_event_func();
    }
    return NULL;
}    



void *do_epoll_control(void *arg) {
    HostEpollControlData output;
    HostSocketIORequest io_request;
    HostSocketIOResponse io_response;
    epoll_event ep_event;
    bool has_data;

    std::vector<char*> buffers;
    int buf_cnt = 10240;
    for (int i = 0; i < buf_cnt; i++) {
        buffers.push_back((char*)malloc(sizeof(char)*20480));
    }
    int buffers_indicator = 0;

    while (true) {
        //- First work: check epoll control events
        has_data =  epoll_ctl_queue->dequeue(output);
        while (has_data) {
            // printf("%s: epfd = %d, op = %d, fd = %d, socket = %lu, event = %u\n", __FUNCTION__, epoll_fd, output.control_event, output.fd, output.socket_id, output.epoll_event);
            
            if (output.control_event == EPOLL_CTL_DEL) {
                epoll_ctl(epoll_fd, output.control_event, output.fd, NULL);
            } else {
                ep_event.events = output.epoll_event;
                ep_event.data.u64 = output.socket_id;
                epoll_ctl(epoll_fd, output.control_event, output.fd, &ep_event);
            }
            has_data =  epoll_ctl_queue->dequeue(output);

        }
        //- Second work: check socket read events
        has_data = rw_req_queue->dequeue(io_request);
        while (has_data) {
            if (io_request.is_read) {
                // printf("io_request.length = %d\n", io_request.length);
                // char* buf = (char*)malloc((io_request.length));
                int ret = read(io_request.socket_fd, buffers[buffers_indicator%buf_cnt], io_request.length);
                // printf("req_len = %d, fd = %d, read_len = %d\n", io_request.length, io_request.socket_fd, ret);
                io_response.butex = io_request.butex;
                rw_resp_queue->enqueue({io_request.butex, true, ret, io_request.ret_length, io_request.requester_buf, buffers[buffers_indicator%buf_cnt]});
                buffers_indicator++;
            }
            has_data = rw_req_queue->dequeue(io_request);
        }
        //- Third job: check socket write events
        do_write_event_func();
        gettimeofday(&time_of_day_val, NULL);
    }
    return NULL;
}



void *do_write_event(void *arg) {
    while (true) {
        //- Third job: check socket write events
        // while(w_req_queue->dequeue()) {            
        //     clock_gettime(CLOCK_MONOTONIC, &clock_mono_time_spec);
        // }
        // clock_gettime(CLOCK_REALTIME, &clock_real_time_spec);
        //- Use func style
        do_write_event_func();
    }
    return NULL;
}

void ocall_create_host_event_dispatcher() {
    epoll_events_queue = new moodycamel::ReaderWriterQueue<HostEpollData>(4096);
    epoll_ctl_queue = new mpmc_queue::mpmc_bounded_queue_t<HostEpollControlData>(4096);
    rw_req_queue = new mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest>(4096);
    rw_resp_queue = new mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse>(4096);
    w_req_queue = new mpmc_queue::socket_write_queue(4096);
    
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, do_epoll_wait, epoll_events_queue);
    
    pthread_t tid2;
    rc = pthread_create(&tid2, NULL, do_epoll_control, epoll_ctl_queue);
    // rc = pthread_create(&tid2, NULL, do_write_event, NULL);

    shared_ptrs.push_back(epoll_events_queue);
    shared_ptrs.push_back(epoll_ctl_queue);

    shared_ptrs.push_back(rw_req_queue);
    shared_ptrs.push_back(rw_resp_queue);
    shared_ptrs.push_back(w_req_queue);

    shared_ptrs.push_back(&time_of_day_val);
    shared_ptrs.push_back(&clock_real_time_spec);
    shared_ptrs.push_back(&clock_mono_time_spec);
}



#endif