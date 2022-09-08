// Copyright (c) 2017 Baidu.com, Inc. All Rights Reserved
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Authors: Zheng,PengFei(zhengpengfei@baidu.com)

#include "sgxbutil/fd_utility.h"                        // sgxbutil::make_close_on_exec
#include "sgxbutil/memory/singleton_on_pthread_once.h"  // sgxbutil::get_leaky_singleton
#include "braft/file_system_adaptor.h"

namespace braft {

bool PosixDirReader::is_valid() const {
    return _dir_reader.IsValid();
}

bool PosixDirReader::next() {
    bool rc = _dir_reader.Next();
    while (rc && (strcmp(name(), ".") == 0 || strcmp(name(), "..") == 0)) {
        rc = _dir_reader.Next();
    }
    return rc;
}

const char* PosixDirReader::name() const {
    return _dir_reader.name();
}

PosixFileAdaptor::~PosixFileAdaptor() {
}

ssize_t PosixFileAdaptor::write(const sgxbutil::IOBuf& data, off_t offset) {
    return braft::file_pwrite(data, _fd, offset);
}

ssize_t PosixFileAdaptor::read(sgxbutil::IOPortal* portal, off_t offset, size_t size) {
    return braft::file_pread(portal, _fd, offset, size);
}

ssize_t PosixFileAdaptor::size() {
    off_t sz = lseek(_fd, 0, SEEK_END);
    return ssize_t(sz);
}

bool PosixFileAdaptor::sync() {
    return raft_fsync(_fd) == 0;
}

bool PosixFileAdaptor::close() {
    if (_fd > 0) {
        bool res = ::close(_fd) == 0;
        _fd = -1;
        return res;
    }
    return true;
}

static pthread_once_t s_check_cloexec_once = PTHREAD_ONCE_INIT;
static bool s_support_cloexec_on_open = false;

static void check_cloexec(void) {
    int fd = ::open("/dev/zero", O_RDONLY | O_CLOEXEC, 0644);
    s_support_cloexec_on_open = (fd != -1);
    if (fd != -1) {
        ::close(fd);
    }
}

FileAdaptor* PosixFileSystemAdaptor::open(const std::string& path, int oflag, 
                                     const ::google::protobuf::Message* file_meta,
                                     sgxbutil::File::Error* e) {
    (void) file_meta;
    pthread_once(&s_check_cloexec_once, check_cloexec);
    bool cloexec = (oflag & O_CLOEXEC);
    if (cloexec && !s_support_cloexec_on_open) {
        oflag &= (~O_CLOEXEC);
    }
    int fd = ::open(path.c_str(), oflag, 0644);
    if (e) {
        *e = (fd == -1) ? sgxbutil::File::OSErrorToFileError(errno) : sgxbutil::File::FILE_OK;
    }
    if (fd == -1) {
        return NULL;
    }
    if (cloexec && !s_support_cloexec_on_open) {
        sgxbutil::make_close_on_exec(fd);
    }
    return new PosixFileAdaptor(fd);
}

bool PosixFileSystemAdaptor::delete_file(const std::string& path, bool recursive) {
    sgxbutil::FilePath file_path(path);
    return sgxbutil::DeleteFile(file_path, recursive);
}

bool PosixFileSystemAdaptor::rename(const std::string& old_path, const std::string& new_path) {
    return ::rename(old_path.c_str(), new_path.c_str()) == 0;
}

bool PosixFileSystemAdaptor::link(const std::string& old_path, const std::string& new_path) {
    return ::link(old_path.c_str(), new_path.c_str()) == 0;
}

bool PosixFileSystemAdaptor::create_directory(const std::string& path, 
                                         sgxbutil::File::Error* error,
                                         bool create_parent_directories) {
    sgxbutil::FilePath dir(path);
    return sgxbutil::CreateDirectoryAndGetError(dir, error, create_parent_directories);
}

bool PosixFileSystemAdaptor::path_exists(const std::string& path) {
    sgxbutil::FilePath file_path(path);
    return sgxbutil::PathExists(file_path);
}

bool PosixFileSystemAdaptor::directory_exists(const std::string& path) {
    sgxbutil::FilePath file_path(path);
    return sgxbutil::DirectoryExists(file_path);
}

DirReader* PosixFileSystemAdaptor::directory_reader(const std::string& path) {
    return new PosixDirReader(path.c_str());
}

FileSystemAdaptor* default_file_system() {
    static sgxscoped_refptr<PosixFileSystemAdaptor> fs = 
        sgxbutil::get_leaky_singleton<PosixFileSystemAdaptor>();
    return fs.get();
}

int file_error_to_os_error(sgxbutil::File::Error e) {
    switch (e) {
        case sgxbutil::File::FILE_OK: 
            return 0;
        case sgxbutil::File::FILE_ERROR_ACCESS_DENIED:
            return EACCES;
        case sgxbutil::File::FILE_ERROR_EXISTS:
            return EEXIST;
        case sgxbutil::File::FILE_ERROR_NOT_FOUND:
            return ENOENT;
        case sgxbutil::File::FILE_ERROR_TOO_MANY_OPENED:
            return EMFILE;
        case sgxbutil::File::FILE_ERROR_NO_MEMORY:
            return ENOMEM;
        case sgxbutil::File::FILE_ERROR_NO_SPACE:
            return ENOSPC;
        case sgxbutil::File::FILE_ERROR_NOT_A_DIRECTORY:
            return ENOTDIR;
        case sgxbutil::File::FILE_ERROR_IO:
            return EIO;
        default:
            return EINVAL;
    };
}

bool create_sub_directory(const std::string& parent_path,
                          const std::string& sub_path,
                          FileSystemAdaptor* fs,
                          sgxbutil::File::Error* error) {
    if (!fs) {
        fs = default_file_system();
    }
    if (!fs->directory_exists(parent_path)) {
        if (error) {
            *error = sgxbutil::File::FILE_ERROR_NOT_FOUND;
        }
        return false;
    }
    sgxbutil::FilePath sub_dir_path(sub_path);
    if (sub_dir_path.ReferencesParent()) {
        if (error) {
            *error = sgxbutil::File::FILE_ERROR_INVALID_URL;
        }
        return false;
    }
    std::vector<sgxbutil::FilePath> subpaths;

    // Collect a list of all parent directories.
    sgxbutil::FilePath last_path = sub_dir_path;
    subpaths.push_back(sub_dir_path.BaseName());
    for (sgxbutil::FilePath path = last_path.DirName();
            path.value() != last_path.value(); path = path.DirName()) {
        subpaths.push_back(path.BaseName());
        last_path = path;
    }
    sgxbutil::FilePath full_path(parent_path);
    for (std::vector<sgxbutil::FilePath>::reverse_iterator i = subpaths.rbegin();
            i != subpaths.rend(); ++i) {
        if (i->value() == "/") {
            continue;
        }
        if (i->value() == ".") {
            continue;
        }
        full_path = full_path.Append(*i);
        // DLOG(INFO) << "Creating " << full_path.value();
        if (!fs->create_directory(full_path.value(), error, false)) {
            return false;
        }
    }
    return true;
}


} //  namespace braft
