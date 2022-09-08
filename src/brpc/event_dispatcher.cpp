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

#ifndef RUN_OUTSIDE_SGX
#include <openenclave/enclave.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <vector>
#include "switchless/networking.h"
#include "switchless/sys_time.h"
extern std::vector<void*>* shared_ptrs;
#endif

#include <sys/epoll.h>
#include <pthread.h>
#include "google/gflags/gflags.h"                            // DEFINE_int32
#include "sgxbutil/fd_utility.h"                         // make_close_on_exec
#include "sgxbutil/logging.h"                            // LOG
#include "sgxbutil/third_party/murmurhash3/murmurhash3.h"// fmix32
#include "brpc/event_dispatcher.h"
#ifdef BRPC_SOCKET_HAS_EOF
#include "brpc/details/has_epollrdhup.h"
#endif
#include "brpc/reloadable_flags.h"

#include "bthread/bthread.h"
#include <unistd.h>

namespace brpc {
DEFINE_int32(event_dispatcher_num, 1, "Number of event dispatcher");

DEFINE_bool(usercode_in_pthread, false, 
            "Call user's callback in pthreads, use bthreads otherwise");

EventDispatcher::EventDispatcher()
    : _epfd(-1)
    , _stop(false)
    , _tid(0)
    , _consumer_thread_attr(BTHREAD_ATTR_NORMAL)
{
    _epfd = epoll_create(1024 * 1024);
    if (_epfd < 0) {
        PLOG(FATAL) << "Fail to create epoll";
        return;
    }

    CHECK_EQ(0, sgxbutil::make_close_on_exec(_epfd));

#if RUN_OUTSIDE_SGX && USE_NORMAL_FUNCTION
    _wakeup_fds[0] = -1;
    _wakeup_fds[1] = -1;
    if (pipe(_wakeup_fds) != 0) {
        PLOG(FATAL) << "Fail to create pipe";
        return;
    }
#endif    
}

EventDispatcher::~EventDispatcher() {
    Stop();
    Join();
    if (_epfd >= 0) {
        close(_epfd);
        _epfd = -1;
    }
#if RUN_OUTSIDE_SGX && USE_NORMAL_FUNCTION
    if (_wakeup_fds[0] > 0) {
        close(_wakeup_fds[0]);
        close(_wakeup_fds[1]);
    }
#endif    
}

int EventDispatcher::Start(const bthread_attr_t* consumer_thread_attr) {
    if (_epfd < 0) {
        LOG(FATAL) << "epoll was not created";

        return -1;
    }
    
    if (_tid != 0) {
        LOG(FATAL) << "Already started this dispatcher(" << this 
                   << ") in bthread=" << _tid;
        return -1;
    }
    // Set _consumer_thread_attr before creating epoll/kqueue thread to make sure
    // everyting seems sane to the thread.
    _consumer_thread_attr = (consumer_thread_attr  ?
                             *consumer_thread_attr : BTHREAD_ATTR_NORMAL);

    // Polling thread uses the same attr for consumer threads (NORMAL right
    // now). Previously, we used small stack (32KB) which may be overflowed
    // when the older comlog (e.g. 3.1.85) calls com_openlog_r(). Since this
    // is also a potential issue for consumer threads, using the same attr
    // should be a reasonable solution.
    int rc = bthread_start_background(
        &_tid, &_consumer_thread_attr, RunThis, this);   
    if (rc) {
        LOG(FATAL) << "Fail to create epoll/kqueue thread: " << berror(rc);
        return -1;
    }
    return 0;
}

bool EventDispatcher::Running() const {
    return !_stop  && _epfd >= 0 && _tid != 0;
}

void EventDispatcher::Stop() {
    _stop = true;
#if RUN_OUTSIDE_SGX && USE_NORMAL_FUNCTION
    if (_epfd >= 0) {
        epoll_event evt = { EPOLLOUT,  { NULL } };
        epoll_ctl(_epfd, EPOLL_CTL_ADD, _wakeup_fds[1], &evt);
    }
#endif
}

void EventDispatcher::Join() {
    if (_tid) {
        bthread_join(_tid, NULL);
        _tid = 0;
    }
}

int EventDispatcher::AddEpollOut(SocketId socket_id, int fd, bool pollin) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd << " pollin = " << pollin;
    if (_epfd < 0) {
        errno = EINVAL;
        return -1;
    }

    epoll_event evt;
    evt.data.u64 = socket_id;
    evt.events = EPOLLOUT | EPOLLET;
#ifdef BRPC_SOCKET_HAS_EOF
    evt.events |= has_epollrdhup;
#endif
    if (pollin) {
        evt.events |= EPOLLIN;
        if (epoll_ctl(_epfd, EPOLL_CTL_MOD, fd, &evt) < 0) {
            // This fd has been removed from epoll via `RemoveConsumer',
            // in which case errno will be ENOENT
            return -1;
        }
    } else {
        if (epoll_ctl(_epfd, EPOLL_CTL_ADD, fd, &evt) < 0) {
            return -1;
        }
    }
    return 0;
}

int EventDispatcher::RemoveEpollOut(SocketId socket_id, 
                                    int fd, bool pollin) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd << " pollin = " << pollin;
    if (pollin) {
        epoll_event evt;
        evt.data.u64 = socket_id;
        evt.events = EPOLLIN | EPOLLET;
#ifdef BRPC_SOCKET_HAS_EOF
        evt.events |= has_epollrdhup;
#endif
        return epoll_ctl(_epfd, EPOLL_CTL_MOD, fd, &evt);
    } else {
        return epoll_ctl(_epfd, EPOLL_CTL_DEL, fd, NULL);
    }

    return -1;
}

int EventDispatcher::AddConsumer(SocketId socket_id, int fd) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd;
    if (_epfd < 0) {
        errno = EINVAL;
        return -1;
    }
    epoll_event evt;
    evt.events = EPOLLIN | EPOLLET;
    evt.data.u64 = socket_id;
    
#ifdef BRPC_SOCKET_HAS_EOF
    //- TODO: epollrdhup，用于指示对方已经关闭连接，就不需要再读了，如果不使用该标志位，继续处理epollin，发现读到的数据为0，也说明对方关闭连接。可见该标志位能节省一点点时间。但是brpc里面似乎没有用上这个标志位，以后再复核。2021.05.08
    // LOG(INFO) << "Func: " << __FUNCTION__ << "has_epollrdhup = " << has_epollrdhup; 
    evt.events |= has_epollrdhup;
#endif
    return epoll_ctl(_epfd, EPOLL_CTL_ADD, fd, &evt);

    return -1;
}

int EventDispatcher::RemoveConsumer(int fd) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd;
    if (fd < 0) {
        return -1;
    }
    // Removing the consumer from dispatcher before closing the fd because
    // if process was forked and the fd is not marked as close-on-exec,
    // closing does not set reference count of the fd to 0, thus does not
    // remove the fd from epoll. More badly, the fd will not be removable
    // from epoll again! If the fd was level-triggered and there's data left,
    // epoll_wait will keep returning events of the fd continuously, making
    // program abnormal.
    if (epoll_ctl(_epfd, EPOLL_CTL_DEL, fd, NULL) < 0) {
        PLOG(WARNING) << "Fail to remove fd=" << fd << " from epfd=" << _epfd;
        return -1;
    }

    return 0;
}

void* EventDispatcher::RunThis(void* arg) {
    ((EventDispatcher*)arg)->Run();
    return NULL;
}

void EventDispatcher::Run() {
    LOG(INFO) << "EventDispatcher::Run()";
    while (!_stop) {
        epoll_event e[32];
#ifdef BRPC_ADDITIONAL_EPOLL
        // Performance downgrades in examples.
        //- If the value of fourth parameter is 0, then epoll_wait() shall return 
        //- immediately, even if no events are available, in which case the return code shall be 0.
        int n = epoll_wait(_epfd, e, ARRAY_SIZE(e), 0);
        if (n == 0) {
            n = epoll_wait(_epfd, e, ARRAY_SIZE(e), -1);
        }
#else
        const int n = epoll_wait(_epfd, e, ARRAY_SIZE(e), -1);
        VLOG(80) << "Func: " << __FUNCTION__ << " Receive new message";
#endif

        if (_stop) {
            // epoll_ctl/epoll_wait should have some sort of memory fencing
            // guaranteeing that we(after epoll_wait) see _stop set before
            // epoll_ctl.
            break;
        }
        if (n < 0) {
            if (EINTR == errno) {
                // We've checked _stop, no wake-up will be missed.
                continue;
            }
            PLOG(FATAL) << "Fail to epoll_wait epfd=" << _epfd;

            break;
        }
        for (int i = 0; i < n; ++i) {
            if (e[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)
#ifdef BRPC_SOCKET_HAS_EOF
                || (e[i].events & has_epollrdhup)
#endif
                ) {
                // We don't care about the return value.
                VLOG(80) << "Func: " << __FUNCTION__ << " Start input event handler";
                Socket::StartInputEvent(e[i].data.u64, e[i].events, _consumer_thread_attr);
            }

        }
        for (int i = 0; i < n; ++i) {
            if (e[i].events & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                LOG(INFO) << "Func: " << __FUNCTION__ << " pthread-" << pthread_self() << " now can write on sockfd = " << e[i].data.fd;
                // We don't care about the return value.
                Socket::HandleEpollOut(e[i].data.u64);
            }

        }
    }
}

static EventDispatcher* g_edisp = NULL;
static HostEventDispatcher* g_host_edisp = NULL;
static pthread_once_t g_edisp_once = PTHREAD_ONCE_INIT;

static void StopAndJoinGlobalDispatchers() {
    for (int i = 0; i < FLAGS_event_dispatcher_num; ++i) {
        g_edisp[i].Stop();
        g_edisp[i].Join();
    }
}
void InitializeGlobalDispatchers() {
    g_edisp = new EventDispatcher[FLAGS_event_dispatcher_num];
    for (int i = 0; i < FLAGS_event_dispatcher_num; ++i) {
        const bthread_attr_t attr = FLAGS_usercode_in_pthread ?
            BTHREAD_ATTR_PTHREAD : BTHREAD_ATTR_NORMAL;
        CHECK_EQ(0, g_edisp[i].Start(&attr));
    }
    // This atexit is will be run before g_task_control.stop() because above
    // Start() initializes g_task_control by creating bthread (to run epoll/kqueue).
    CHECK_EQ(0, atexit(StopAndJoinGlobalDispatchers));
}

void InitializeGlobalHostDispatchers() {
    g_host_edisp = new HostEventDispatcher;
    g_host_edisp->Start(NULL);

    // CHECK_EQ(0, atexit(StopAndJoinGlobalHostDispatchers));
}

EventDispatcher& GetGlobalEventDispatcher(int fd) {
#if (!defined(RUN_OUTSIDE_SGX) && USE_HOST_EVENT_DISPATCHER)
    pthread_once(&g_edisp_once, InitializeGlobalHostDispatchers);
    return g_host_edisp[0];
#else
    pthread_once(&g_edisp_once, InitializeGlobalDispatchers);
    if (FLAGS_event_dispatcher_num == 1) {
        return g_edisp[0];
    }
    int index = sgxbutil::fmix32(fd) % FLAGS_event_dispatcher_num;
    return g_edisp[index];
#endif    
}


//- ********************* Following is HostEventDispatcher *********************

HostEventDispatcher::HostEventDispatcher() {
    _stop = false;
    _consumer_thread_attr = BTHREAD_ATTR_NORMAL;
    _tid = 0;
#ifndef RUN_OUTSIDE_SGX    
    //- ocall to create two new threads in the host side to
    //- 1. do epoll_wait; 2. handle requests (epoll_ctl) from the enclave
    ocall_create_host_event_dispatcher();
    // fprintf(stderr, "ptr to epoll event: %p\n", shared_ptrs->at(0));
    // fprintf(stderr, "ptr to epoll control: %p\n", shared_ptrs->at(1));
    epoll_events_q = static_cast<sgx_moodycamel::ReaderWriterQueue<HostEpollData>*>(shared_ptrs->at(0));
    epoll_ctl_q = static_cast<sgx_mpmc_queue::mpmc_bounded_queue_t<HostEpollControlData>*>(shared_ptrs->at(1));
    setup_socket_working_queues();
    setup_shared_time_variable();
    shared_ptrs->clear();
#endif    
}

HostEventDispatcher::~HostEventDispatcher() {
    //- Stop and join
}

int HostEventDispatcher::Start(const bthread_attr_t* consumer_thread_attr) {
#ifndef RUN_OUTSIDE_SGX
    //- Create a bthread to poll incomming client requests indefinitely
    int rc = bthread_start_background(
        &_tid, &_consumer_thread_attr, RunThis, this);   
    if (rc) {
        LOG(FATAL) << "Fail to create epoll/kqueue thread: " << berror(rc);
        return -1;
    }
    //- Create another bthread to poll socket IO indefinitely
    bthread_t tid;
    rc = bthread_start_background(
        &tid, &_consumer_thread_attr, poll_socket_io_results, NULL);
    if (rc) {
        LOG(FATAL) << "Fail to create epoll/kqueue thread: " << berror(rc);
        return -1;
    }
#endif
    return 0;
}

int HostEventDispatcher::AddEpollOut(SocketId socket_id, int fd, bool pollin) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd << " pollin = " << pollin;

    HostEpollControlData ctl_data;
    ctl_data.socket_id = socket_id;
    ctl_data.fd = fd;
    ctl_data.epoll_event = EPOLLOUT | EPOLLET;

    if (pollin) {
        ctl_data.epoll_event |= EPOLLIN;
        ctl_data.control_event = EPOLL_CTL_MOD;
    } else {
        ctl_data.control_event = EPOLL_CTL_ADD;
    }
    epoll_ctl_q->enqueue(ctl_data);
    return 0;
}

int HostEventDispatcher::RemoveEpollOut(SocketId socket_id, 
                                    int fd, bool pollin) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd << " pollin = " << pollin;
    HostEpollControlData ctl_data;
    ctl_data.fd = fd;
    if (pollin) {
        ctl_data.socket_id = socket_id;
        ctl_data.epoll_event = EPOLLIN | EPOLLET;
        ctl_data.control_event = EPOLL_CTL_MOD;
    } else {
        ctl_data.control_event = EPOLL_CTL_DEL;
    }
    epoll_ctl_q->enqueue(ctl_data);
    return 0;
}

int HostEventDispatcher::AddConsumer(SocketId socket_id, int fd) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd;
    epoll_ctl_q->enqueue({socket_id, EPOLLIN | EPOLLET, EPOLL_CTL_ADD, fd});
    return 0;
}

int HostEventDispatcher::RemoveConsumer(int fd) {
    LOG(INFO) << "Func: " << __FUNCTION__ << " operating on fd = " << fd;
    if (fd < 0) {
        return -1;
    }
    HostEpollControlData ctl_data;
    ctl_data.fd = fd;
    ctl_data.control_event = EPOLL_CTL_DEL;
    epoll_ctl_q->enqueue(ctl_data);
    return 0;
}

void* HostEventDispatcher::RunThis(void* arg) {
    ((HostEventDispatcher*)arg)->Run();
    return NULL;
}

void HostEventDispatcher::Run() {
    HostEpollData epoll_data;
    while (true) {
        while (epoll_events_q->try_dequeue(epoll_data)) {
            LOG(INFO) << "Func: " << __FUNCTION__ << " event = " << epoll_data.epoll_event
                << ", socket = " << epoll_data.socket_id;

            if (epoll_data.epoll_event & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
                // We don't care about the return value.
                LOG(INFO) << "Func: " << __FUNCTION__ << " Start input event handler";
                Socket::StartInputEvent(epoll_data.socket_id, epoll_data.epoll_event, _consumer_thread_attr);
            }
            if (epoll_data.epoll_event & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                LOG(INFO) << "Func: " << __FUNCTION__ << " pthread-" << pthread_self() << " now can write on sockfd = " << epoll_data.socket_id;
                // We don't care about the return value.
                Socket::HandleEpollOut(epoll_data.socket_id);
            }
        }
        // poll_socket_io_results_func();
        // LOG(ERROR) << "Func: " << __FUNCTION__ << " Empty epoll_events_q.";
    }
}

} // namespace brpc
