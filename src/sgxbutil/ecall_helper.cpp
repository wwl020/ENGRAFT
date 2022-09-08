#include "sgxbutil/ecall_helper.h"
#include <algorithm>
#include <vector>

#ifndef RUN_OUTSIDE_SGX
#include "interface_t.h"
#endif

static std::vector<PthreadTask> pthread_tasks;
static std::vector<bool> task_used;
static std::vector<bool> timer_task_used;
static pthread_mutex_t mutex_tasks = PTHREAD_MUTEX_INITIALIZER;

pthread_task_id generate_pthread_task(void * (*fn)(void*), void* __restrict arg) {
    ::pthread_mutex_lock(&mutex_tasks);
    std::vector<bool>::iterator used_it = find(task_used.begin(), task_used.end(), false);
    //- Run out of
    if (used_it == task_used.end()) {
        PthreadTask pt(fn, arg);
        pthread_tasks.push_back(pt);
        task_used.push_back(true);
        ::pthread_mutex_unlock(&mutex_tasks);
        // LOG(INFO) << __FUNCTION__ << " get_res used up, Develop DEBUG *id = " << *id;
        return task_used.size()-1;
    }
    size_t id = used_it - task_used.begin();
    task_used[id] = true;
    pthread_tasks[id].fn = fn;
    pthread_tasks[id].arg = arg;
    ::pthread_mutex_unlock(&mutex_tasks);
    return id;
}


void ecall_pthread_general(pthread_task_id task_id) {
    PthreadTask pt = pthread_tasks[task_id];
    //- If pt.fn is TaskControl::worker_thread, then it will stuck in
    //- pt.fn. Thus, task_used[task_id] is not set to false.
    //- But this is ok since PthreadTask struct don't occupy much memory.
    pt.fn(pt.arg);
    ::pthread_mutex_lock(&mutex_tasks);
    task_used[task_id] = false;
    ::pthread_mutex_unlock(&mutex_tasks);
}
