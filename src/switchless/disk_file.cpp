#include "switchless/disk_file.h"
#include "sgxbutil/third_party/working_queues/socket_write_queue.h"
extern sgx_mpmc_queue::socket_write_queue* w_req_queue;

ssize_t disk_file_writev(int fd, const struct iovec* vector, int count) {
    // VLOG(0) << "Func: " << __FUNCTION__;
    int nw = 0;
    w_req_queue->enqueue(fd, vector, count, nw);
    return nw;
}