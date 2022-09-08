// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.


#ifndef BRPC_EVENT_DISPATCHER_H
#define BRPC_EVENT_DISPATCHER_H

#include "sgxbutil/macros.h"                     // DISALLOW_COPY_AND_ASSIGN
#include "bthread/types.h"
#include "brpc/socket.h"                     // Socket, SocketId
#include "sgxbutil/third_party/readerwriterqueue/readerwriterqueue.h"
#include "sgxbutil/third_party/working_queues/mpsc_vyukov.h"
#include "sgxbutil/third_party/working_queues/mpmc_bounded.h"



namespace brpc {

// Dispatch edge-triggered events of file descriptors to consumers
// running in separate threads.
class EventDispatcher {
friend class Socket;
public:
    EventDispatcher();
    
    virtual ~EventDispatcher();

    // Start this dispatcher in a bthread.
    // Use |*consumer_thread_attr| (if it's not NULL) as the attribute to
    // create bthreads running user callbacks.
    // Returns 0 on success, -1 otherwise.
    virtual int Start(const bthread_attr_t* consumer_thread_attr);

    // True if this dispatcher is running in a thread
    bool Running() const;

    // Stop thread of this dispatcher.
    void Stop();

    // Suspend calling thread until thread of this dispatcher stops.
    void Join();

    // When edge-triggered events happen on `fd', call
    // `on_edge_triggered_events' of `socket_id'.
    // Notice that this function also transfers ownership of `socket_id',
    // When the file descriptor is removed from internal epoll, the Socket
    // will be dereferenced once additionally.
    // Returns 0 on success, -1 otherwise.
    virtual int AddConsumer(SocketId socket_id, int fd);

    // Watch EPOLLOUT event on `fd' into epoll device. If `pollin' is
    // true, EPOLLIN event will also be included and EPOLL_CTL_MOD will
    // be used instead of EPOLL_CTL_ADD. When event arrives,
    // `Socket::HandleEpollOut' will be called with `socket_id'
    // Returns 0 on success, -1 otherwise and errno is set
    virtual int AddEpollOut(SocketId socket_id, int fd, bool pollin);
    
    // Remove EPOLLOUT event on `fd'. If `pollin' is true, EPOLLIN event
    // will be kept and EPOLL_CTL_MOD will be used instead of EPOLL_CTL_DEL
    // Returns 0 on success, -1 otherwise and errno is set
    virtual int RemoveEpollOut(SocketId socket_id, int fd, bool pollin);

private:
    DISALLOW_COPY_AND_ASSIGN(EventDispatcher);

    // Calls Run()
    static void* RunThis(void* arg);

    // Thread entry.
    void Run();

    // The epoll to watch events.
    int _epfd;

//- Inherited by host event dispatcher    
public:
    // false unless Stop() is called.
    volatile bool _stop;

    // identifier of hosting bthread
    bthread_t _tid;

    // The attribute of bthreads calling user callbacks.
    bthread_attr_t _consumer_thread_attr;

    // Remove the file descriptor `fd' from epoll.
    virtual int RemoveConsumer(int fd);

    //- OE don't support pipe
    //- TODO: 由于enclave里面不支持管道，所以和这个变量相关的代码都注释掉了，暂时没发现问题
    //- 如下描述，该变量的作用在于通知 EventDispatcher 退出，没有应该问题不大
    // Pipe fds to wakeup EventDispatcher from `epoll_wait' in order to quit
#if RUN_OUTSIDE_SGX && USE_NORMAL_FUNCTION
    int _wakeup_fds[2];
#endif    
};

EventDispatcher& GetGlobalEventDispatcher(int fd);

typedef struct HostEpollData{
    //- uint64_t
    SocketId socket_id;
    //- In/Out
    uint32_t epoll_event;
    HostEpollData(SocketId a, uint32_t b): socket_id(a), epoll_event(b){}
    HostEpollData(): socket_id(0), epoll_event(0){}
} HostEpollData;

typedef struct HostEpollControlData{
    //- uint64_t
    SocketId socket_id;
    //- In/Out
    uint32_t epoll_event;
    //- Control type: EPOLL_CTL_MOD/ADD/DEL
    int control_event;
    //- file descriptor
    int fd;
    HostEpollControlData(SocketId a, uint32_t b, int c, int d): 
        socket_id(a), epoll_event(b), control_event(c), fd(d) {}
    HostEpollControlData(): socket_id(0), epoll_event(0), control_event(0), fd(-1) {}
} HostEpollControlData;

class HostEventDispatcher : public EventDispatcher {
public:    
    HostEventDispatcher();
    ~HostEventDispatcher();
    int Start(const bthread_attr_t* consumer_thread_attr);
    int AddConsumer(SocketId socket_id, int fd);
    int RemoveConsumer(int fd);
    int AddEpollOut(SocketId socket_id, int fd, bool pollin);
    int RemoveEpollOut(SocketId socket_id, int fd, bool pollin);

private:
    //- SPSC queue, host: producer, enclave: consumer
    sgx_moodycamel::ReaderWriterQueue<HostEpollData>* epoll_events_q;
    //- MPSC queue, enclave threads: producer, host: consumer
    sgx_mpmc_queue::mpmc_bounded_queue_t<HostEpollControlData>* epoll_ctl_q;
    static void* RunThis(void* arg);
    void Run();
};

} // namespace brpc
#endif  // BRPC_EVENT_DISPATCHER_H
