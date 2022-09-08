#ifndef RUN_OUTSIDE_SGX
#include <byteswap.h> 
#include <openssl/ssl.h>

// //- liboehostsock
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
//- Test I/O
#include <sys/uio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
//- thread
#include <pthread.h>
#include "interface_t.h"

#include <netdb.h>                             // gethostbyname_r
#include <iosfwd>
#include <string>
#include <sstream>
#include <iostream>

#include "google/gflags/gflags.h"
#include "sgxbutil/atomicops.h"
#include "sgxbutil/logging.h"


#include "sgxbutil/third_party/readerwriterqueue/readerwriterqueue.h"
#include "brpc/event_dispatcher.h"  //- To test event dispatcher
#include "sgxbutil/enclave.h"
#include "switchless/networking.h"

//- For distributed counter/state_manager testing
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/state_cont/distri_state_mgr.h"
DECLARE_int32(port);

//- For merkel tree testing
#include "sgxbutil/third_party/merklecpp/merklecpp.h"
#include "sgxbutil/state_cont/openssl_utils.h"

//- For fdatasync test
#include "sgxbutil/fd_utility.h"

//- A vector shared with the enclave, which involves pointers to shared memory
std::vector<void*>* shared_ptrs;

//- 启动OE挂载文件系统
void setup_fs(int port) {
    oe_result_t result;
    //- Test liboehostfs
    if ((result = oe_load_module_host_file_system()) != OE_OK) {
        fprintf(
            stderr,
            "Call to oe_load_module_host_file_system failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
    // Must mount the file system first
    std::string mount_str = "/home/jetli/temppppp/sgx-raft-running/";
    mount_str += std::to_string(port);
    mount_str += "/";
    LOG(INFO) << "Func: " << __FUNCTION__ << " Mount Path = " << mount_str;
    if (mount(mount_str.c_str(), "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0) {
        fprintf(
            stderr,
            "Mount OE_HOST_FILE_SYSTEM failes: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
    mkdir("/data/log",0755);
}



void setup_socket() {
    setup_ssl_read_write_func();

    oe_result_t result;
    // - Test liboehostsock
    if ((result = oe_load_module_host_socket_interface()) != OE_OK) {
        fprintf(
            stderr,
            "Call to oe_load_module_host_socket_interface failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }

    if ((result = oe_load_module_host_resolver()) != OE_OK) {
        fprintf(
            stderr,
            "Call to oe_load_module_host_resolver failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
    //- For epoll
    if ((result = oe_load_module_host_epoll()) != OE_OK) {
        fprintf(
            stderr,
            "Call to oe_load_module_host_epoll failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
    }
}

//- port is 0, 1, 2, 3...
void enclave_setup(int port, void* ptr) {
    setup_fs(port);
    setup_socket();
    shared_ptrs = static_cast<std::vector<void*>*>(ptr) ;
    fprintf(stdout, "Hello from the enclave, f = %s\n", __PRETTY_FUNCTION__);
}

void test_switchless_ocall() {
    //- million
    int cnt = 1000000;
    sgxbutil::Timer timer;
    timer.start();
    timeval now;
    for (int i = 0; i < cnt; i++) {
        ocall_swless_add();
        ocall_gettimeofday(&now);
    }
    timer.stop();
    fprintf(stdout, "ocall_switchless, time = %lfms\n", timer.m_elapsed(0.0));

    timer.start();
    for (int i = 0; i < cnt; i++) {
        ocall_reg_add();
        // ocall_gettimeofday_switch(&now);
        // ocall_gettimeofday_nocopy();
    }
    timer.stop();
    fprintf(stdout, "ocall_regular, time = %lfms\n", timer.m_elapsed(0.0));
}

void test_log_time() {
    int count = 10000;
    sgxbutil::Timer timer;
    timer.start();
    timeval now;
    uint64_t current_nano_sec = 0;
    struct tm local_tm = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};
    
    for (int i = 0; i < count; i++) {
        //- nearly 50us once
        // LOG(ERROR) << "Func: " << __FUNCTION__ ;

        //- 0.8us once (switchless)
        // ocall_gettimeofday(&now);

        //- 4us once (switch)
        ocall_gettimeofday_switch(&now);
        
        //- 1.2us (switchless), 4us(switch)
        // ocall_get_logging_time(&local_tm, &current_nano_sec);

        //- 12-13us once
        // fprintf(stderr, "hello....\n");
    }
    timer.stop();
    LOG(ERROR) << "Func: " << __FUNCTION__ << " time = " << timer.u_elapsed(0.0) << " us";
}

void test_host_event_dispatcher() {
    brpc::EventDispatcher& disp = brpc::GetGlobalEventDispatcher(1);
    int i = 1;
    while (true) {
        i++;
        sleep(2);
        LOG(INFO) << "Func: " << __FUNCTION__ << " wake up...";
        disp.AddConsumer(100, i);
        disp.RemoveConsumer(1001);
    }
}

void test_socket_fd() {
    while (true) {
        sleep(1);
        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        LOG(INFO) << "Func: " << __FUNCTION__ << " socket fd = " << sfd;
    }

}

void *test_butex_wait(void* arg) {
    uint32_t* butex = static_cast<uint32_t*>(arg);
    VLOG(0) << "Func: " << __FUNCTION__ << " Waiting on " << butex;
    bthread::butex_wait(butex, 0, NULL);
    VLOG(0) << "Func: " << __FUNCTION__ << " Waking on " << butex;
    return NULL;
}

void *test_butex_wake(void* arg) {
    uint32_t* butex = static_cast<uint32_t*>(arg);
    // __atomic_store_n(butex, 1, __ATOMIC_RELEASE);
    *butex = 1;
    bthread::butex_wake(butex);
    VLOG(0) << "Func: " << __FUNCTION__ << " Trying to wake butex = " << butex;
    return NULL;
}

void test_bthread_butex() {
    uint32_t* butex = bthread::butex_create_checked<uint32_t>();
    *butex = 0;
    bthread_t tid;
    bthread_start_background(&tid, NULL, test_butex_wait, butex);
    // sleep(1);
    bthread_start_background(&tid, NULL, test_butex_wake, butex);
    sleep(100);
}

void test_swless_clock_read() {
    timeval* now2 = static_cast<timeval*>(shared_ptrs->at(0));
    const size_t sizeof_timeval = sizeof(timeval);
    int count = 10000;
    sgxbutil::Timer timer;
    timer.start();
    timeval now;
    uint64_t current_nano_sec = 0;
    struct tm local_tm = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};
    
    for (int i = 0; i < count; i++) {
        //- 2.2ns once (customized switchless)
        // ocall_gettimeofday(&now);
        memcpy(&now, now2, sizeof_timeval);

        //- 4us once (switch)
        // ocall_gettimeofday_switch(&now);
    }
    timer.stop();
    LOG(ERROR) << "Func: " << __FUNCTION__ << " time = " << timer.u_elapsed(0.0) << " us";
    LOG(ERROR) << "Func: " << __FUNCTION__ << " res.sec = " << now.tv_sec;
}

void test_dist_counter() {
    sgxbutil::MonoCounterManager& dc_manager = sgxbutil::GetGlobalMonoCntManager();
    LOG(INFO) << "Func: " << __FUNCTION__ << " Read log counter, val = " 
        << dc_manager.read_counter(0);
    if (FLAGS_port == 8100) {
        dc_manager.increase_counter(0);
    }
}

void test_distri_state_mgr() {
    sgxbutil::DistributedStateManager* state_mgr = sgxbutil::GetGlobalDistributedStateManager();
    state_mgr->print_manager_info();
}

void test_merkle_tree() {
    merkle::Tree mt;
    const int tree_nodes = 64;
    std::string root_hash_strs[tree_nodes+1];
    for (int j = 0; j < tree_nodes; j++) {
        const int input_size = 64;
        uint8_t input[input_size] = {0};
        for (int i = 0; i < input_size; i++) {
            //- Randomize the input
            input[i] = i%(12*(j+1));
        }

        uint8_t sha256_hash[32] = {0};
        sgxbutil::generate_sha256_hash(input, input_size, sha256_hash);
        merkle::Hash hash(sha256_hash);
        mt.insert(hash);
        root_hash_strs[j] = mt.root().to_string();
    }
    VLOG(79) << "merkle tree min_index = " << mt.min_index() 
        << " max_index = " << mt.max_index();
    int retract_index = 60;
    mt.retract_to(retract_index);
    merkle::Hash root_hash;
    root_hash = mt.root();
    VLOG(79) << "merkle_tree info: " << mt.statistics.to_string();
    VLOG(79) << "root_hash_string = " << root_hash.to_string();
    VLOG(79) << "root_hash_strs[" << retract_index << "] = " 
        << root_hash_strs[retract_index];
    VLOG(79) << "Equal: " << (root_hash == root_hash_strs[retract_index]);
}

//
void test_fdatasync() {
    // int fd1 = ::open("./fdatasync_file", O_DSYNC | O_RDWR | O_CREAT | O_TRUNC, 0644);
    int fd1 = ::open("./fdatasync_file", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd1 < 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " open file failed " << berror();
    }
    sgxbutil::make_close_on_exec(fd1);
    //- Pre-allocate 10MB space
    if (ocall_fallocate(fd1, 0, 10*1024*1024) != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " fallocate space failed";
    }

    //- 960 + 64 = 1024 bytes = 1KB
    const int test_data_size = 960;
    const int test_data_header_size = 64;
    char test_data[test_data_size];
    char test_data_header[test_data_header_size];
    for (int i = 0; i < test_data_size; i++) test_data[i] = '0';
    for (int i = 0; i < test_data_header_size; i++) test_data_header[i] = '1';

    sgxbutil::IOBuf test_iobuf;
    test_iobuf.append(test_data, test_data_size);
    const int test_count = 1000;
    double sync_time[test_count];
    for (int cnt = 0; cnt < test_count; cnt++) {
        sgxbutil::IOBuf header;
        sgxbutil::IOBuf data;
        header.append(test_data_header, test_data_header_size);
        data.append(test_data, test_data_size);
        sgxbutil::IOBuf* pieces[2] = { &header, &data };

        const size_t to_write = header.length() + data.length();
        size_t start = 0;
        ssize_t written = 0;
        sgxbutil::Timer sync_timer;
        sync_timer.start();
        while (written < (ssize_t)to_write) {
            const ssize_t n = sgxbutil::IOBuf::cut_multiple_into_file_descriptor(
                    fd1, pieces + start, ARRAY_SIZE(pieces) - start);
            if (n < 0) {
                LOG(ERROR) << "Fail to write to fd=" << fd1;
            }
            written += n;
            //- Update variable start
            for (;start < ARRAY_SIZE(pieces) && pieces[start]->empty(); ++start) {}
        }
        int ret = 0;
        ret = fdatasync(fd1);
        // ret = fsync(fd1);
        if (ret != 0) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " sync error! cnt = " << cnt;
            break;
        }
        sync_timer.stop();
        sync_time[cnt] = sync_timer.m_elapsed(0);
        // VLOG(79) << " TIME_OF fdatasync = " << sync_timer.m_elapsed(0) << " ms";
        usleep(10*1000);
    }
    for (int i = 0; i < test_count; i++) {
        VLOG(79) << " TIME_OF fdatasync = " << sync_time[i] << " ms";
    }
}

void enclave_test() {
    // test_log_time();
    // test_switchless_ocall();
    // test_host_event_dispatcher();
    // test_socket_fd();
    // test_enclave_ptr_passing();
    // test_bthread_butex();
    // test_swless_clock_read();
    // test_dist_counter();
    // test_distri_state_mgr();
    // test_merkle_tree();
    test_fdatasync();
    // sleep(30);
    LOG(ERROR) << "enclave_test ending...";
}

void enclave_test_shared_mem(void* ptr) {
    sgx_moodycamel::ReaderWriterQueue<brpc::HostEpollData>* epoll_events_q
        = static_cast<sgx_moodycamel::ReaderWriterQueue<brpc::HostEpollData>*>(ptr);
    bool enqueue_success;
    for (int i = 0; i < 30; i++) {
        enqueue_success = epoll_events_q->try_enqueue(brpc::HostEpollData(1,i));
        if (!enqueue_success) {
            LOG(ERROR) << "Func: " << __FUNCTION__ << " fail to enqueue...";
        }
    }  
}

#endif