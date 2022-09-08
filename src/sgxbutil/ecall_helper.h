#include <stdint.h>
#include <pthread.h>

#ifndef SGXBUTIL_ECALL_HELPER_H
#define SGXBUTIL_ECALL_HELPER_H

typedef uint64_t pthread_task_id;

struct PthreadTask {
    // The identifier. It does not have to be here, however many code is
    // simplified if they can get tid from TaskMeta.
    pthread_t tid;

    // User function and argument
    void* (*fn)(void*);
    void* arg;

    // Attributes creating this task
    pthread_attr_t attr;

public:
    // Only initialize [Not Reset] fields, other fields will be reset in
    // bthread_start* functions
    PthreadTask() {
    }
    PthreadTask(void* (*fn)(void*), void* arg) {
        this->fn = fn;
        this->arg = arg;
    }
        
    ~PthreadTask() {
    }
};

pthread_task_id generate_pthread_task(void * (*fn)(void*), void* __restrict arg);

#endif //- SGXBUTIL_ECALL_HELPER_H