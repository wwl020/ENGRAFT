#ifndef SWITCHLESS_DISK_FILE_H
#define SWITCHLESS_DISK_FILE_H
#include <stdint.h>
#include <sys/types.h>

ssize_t disk_file_writev(int fd, const struct iovec* vector, int count);

#endif