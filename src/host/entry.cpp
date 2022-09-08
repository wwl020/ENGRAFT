#ifndef RUN_OUTSIDE_SGX

//- Socket things
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iostream>
#include <stdio.h>
#include "interface_u.h"
#include <openenclave/host.h>
#include <vector>
#include "host_utils.h"
#include "duplicated_things.h"
#include "host_tpm_utils.h"
#include <signal.h>

oe_enclave_t* enclave = NULL;
//- A vector shared with the enclave, which involves pointers to shared memory
std::vector<void*> shared_ptrs;
int node_num = 0;

void ocall_exit(int val) {
    exit(val);
}

void host_helloworld() {
    fprintf(stdout, "Enclave called into host to print: Hello World!\n");
}

void ocall_swless_add() {
    int i = 1;
    i++;
}

void ocall_reg_add() {
    int i = 1;
    i++;
}

void* test_shared_mem(void* arg) {
    enclave_test_shared_mem(enclave, arg);
    return NULL;
}

void test_custom_switchless() {
    moodycamel::ReaderWriterQueue<HostEpollData> epoll_events_q(100);
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, test_shared_mem, &epoll_events_q);
    sleep(3);
    // You can also peek at the front item of the queue (consumer only)
    HostEpollData number;
    while (epoll_events_q.try_dequeue(number)) {
        fprintf(stderr, "num1 = %ld, num2 = %u\n", number.socket_id, number.epoll_event);
    }
    HostEpollData* front = epoll_events_q.peek(); 
    // Returns nullptr if the queue was empty
    assert(front == nullptr);
}

void* test_enclave_ptr_assist(void* arg) {
    //- In enclave_test, continue to call test_enclave_ptr_passing
    enclave_test(enclave);
    return NULL;
}
//- Can host access enclave pointer (the pointer itself, not the value)?
void test_enclave_ptr() {
    mpmc_queue::mpmc_bounded_queue_t<HostSocketIORequest> req_q(1024);
    mpmc_queue::mpmc_bounded_queue_t<HostSocketIOResponse> resp_q(1024);
    shared_ptrs.push_back(&req_q);
    shared_ptrs.push_back(&resp_q);
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, test_enclave_ptr_assist, NULL);
    sleep(1);
    HostSocketIORequest host_req;
    bool success = req_q.dequeue(host_req);
    if (success) {
        printf("HOST: a = %p, *a not accessible\n", host_req.butex);
    }
    HostSocketIOResponse host_resp(host_req.butex);
    printf("HOST: enque start.\n");
    resp_q.enqueue(host_resp);
    printf("HOST: enque finish.\n");
    sleep(1000);
}

static void signal_handler(int signo) {
    if (signo == SIGPIPE) {
        fprintf(stderr, "Received signal SIGPIPE, Broken pipe.\n");
    }
}

INITIALIZE_EASYLOGGINGPP
#define ELPP_THREAD_SAFE
int main(int argc, const char* argv[]) {
    //- CONFIGURATION CODE
    setbuf(stdout, NULL);
    //- 1. Setting easy logging
    el::Configurations defaultConf;
    defaultConf.setToDefault();
    //- 1.1 Host's output will not be printed in stdout.
    defaultConf.setGlobally(el::ConfigurationType::ToStandardOutput, "false");
    el::Loggers::reconfigureLogger("default", defaultConf);
    
    //- Set signal handler
    signal(SIGPIPE, signal_handler);

    int port_num = atoi(argv[2]+6);
    printf("Entering main function, port_num = %d \n", port_num);
    node_num = port_num - 8100;
    oe_result_t result;
    int ret = 1;
    int in = 100;

    //- Set flags to zero will enable release mode
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    printf("Creating enclave\n");
    
    // Create the enclave
    oe_enclave_setting_context_switchless_t switchless_setting = {
        2,  // number of host worker threads
        0}; // number of enclave worker threads.
    oe_enclave_setting_t enc_setting;
    enc_setting.setting_type = OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS;
    enc_setting.u.context_switchless_setting = &switchless_setting;
    oe_enclave_setting_t settings[] = {enc_setting};
    result = oe_create_interface_enclave(
        // argv[1], OE_ENCLAVE_TYPE_AUTO, flags, settings, OE_COUNTOF(settings), &enclave);
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
        // argv[1], OE_ENCLAVE_TYPE_AUTO, 0, NULL, 0, &enclave); //- Release mode    
    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "oe_create_helloworld_enclave(): result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }
    printf("Enclave created\n");
    std::cout << "enclave = " << enclave << std::endl;

    // Call into the enclave
    
    //- 该函数负责挂载操作，8100端口传入0就可以了，代表使用0文件夹
    //- 这里假定了端口号从8100开始
    enclave_setup(enclave, node_num, &shared_ptrs);

    result = start_counter_server(enclave, port_num);
    
    // enclave_test(enclave);
    // test_custom_switchless();
    // test_enclave_ptr();
    

    if (result != OE_OK)
    {
        fprintf(
            stderr,
            "calling into enclave_helloworld failed: result=%u (%s)\n",
            result,
            oe_result_str(result));
        goto exit;
    }

    ret = 0;

exit:
    // Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);
    return ret;
}

#endif