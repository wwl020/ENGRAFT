// Copyright (c) 2015 Baidu.com, Inc. All Rights Reserved
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

// Authors: Wang,Yao(wangyao02@baidu.com)

#include "sgxbutil/iobuf.h"
#include "sgxbutil/sys_byteorder.h"

#include "braft/protobuf_file.h"
#include "sgxbutil/state_cont/openssl_utils.h"
DEFINE_bool(use_distributed_counters, true, "Use distributed counters or not");

namespace braft {

ProtoBufFile::ProtoBufFile(const char* path, FileSystemAdaptor* fs) 
    : _path(path), _fs(fs) {
    if (_fs == NULL) {
        _fs = default_file_system();
    }
}

int ProtoBufFile::save(const google::protobuf::Message* msg, 
                    bool sync, sgxbutil::CounterID* counter_id, int flag) {
    std::string tmp_path(_path);
    tmp_path.append(".tmp");
    LOG(INFO) << "Func: " << __FUNCTION__ << " tmp_path = " << tmp_path;

    sgxbutil::File::Error e;
    //- PosixFileAdaptor
    //- fs->open will call PosixFileSystemAdaptor::open
    FileAdaptor* file = _fs->open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, NULL, &e);
    if (!file) {
        LOG(ERROR) << "open file failed, path: " << _path
                     << ": " << sgxbutil::File::ErrorToString(e);
        return -1;
    }
    std::unique_ptr<FileAdaptor, DestroyObj<FileAdaptor> > guard(file);

    //- Get counter value
    sgxbutil::MonoCounterManager& manager = sgxbutil::GetGlobalMonoCntManager();
    sgxbutil::CounterVal counter_value = 0;
    if (*counter_id == -1) {
        if (FLAGS_use_distributed_counters) {
            *counter_id = flag;
        } else {
            *counter_id =  manager.get_counter();
        }
    }
    counter_value = manager.read_counter(*counter_id);
    LOG(INFO) << "Func: " << __FUNCTION__ << " REach here...";

    //- Get initialization vector, seal key and plain text
    //- Buffer for iv
    sgxbutil::Timer timer;
    timer.start();
    unsigned char iv[12];
    sgxbutil::get_init_vector(iv, sizeof(iv));
    CHECK(sizeof(iv)==12);

    //- Buffer for key
    unsigned char key[32];
    sgxbutil::get_sgx_seal_key_128(key);

    //- Buffer for plain text
    int msg_byte_size = msg->ByteSize();    
    unsigned char msg_plain[msg_byte_size];
    bool success = msg->SerializeToArray(msg_plain, msg_byte_size);
    if (!success) {
        LOG(ERROR) << "SerializeToArray failed.";
        return -1;
    }
    int plaintext_len = strlen((char*)msg_plain);
    // LOG(INFO) << "plaintext_len = " << plaintext_len;

    //- Buffer for cipher text
    unsigned char msg_cipher[plaintext_len];

    //- Buffer for the mac tag
    unsigned char mac[16];
    uint32_t counter_index = (uint32_t)(*counter_id);
    
    //- Construct Additional Authenticated Data (AAD) from counter info
    unsigned char *aad = (unsigned char*)malloc(sizeof(unsigned char) * 12);
    // LOG(INFO) << "sizeof(aad) = " << sizeof(aad);
    // LOG(INFO) << "sizeof(uint32_t) = " << sizeof(uint32_t);
    // LOG(INFO) << "sizeof(uint64_t) = " << sizeof(uint64_t);
    memcpy(aad, (unsigned char*)&counter_index, sizeof(uint32_t));
    memcpy(aad+4, (unsigned char*)&counter_value, sizeof(uint64_t));
    // LOG(INFO) << "print counter_value = " << *((uint64_t*)(aad+4));
    // LOG(INFO) << "print counter_index = " << *((uint32_t*)(aad));

    //- Do encryption
    // LOG(NOTICE) << "Func: " << __FUNCTION__ << " gcm_encrypt length = "
    //     << plaintext_len << " bytes" << " file = " << tmp_path;
    int32_t cipher_len = sgxbutil::gcm_encrypt(msg_plain, plaintext_len, aad, 12, key, iv, 12, msg_cipher, mac);
    timer.stop();
    VLOG(85) << "cipher_len = " << cipher_len << " TIME_OF pb file encryption = "
        << timer.m_elapsed(0.0) << " ms";

    timer.start();
    //- Start to put data to iobuf
    sgxbutil::IOBuf write_iobuf;

    //- 1. Put iv in write_iobuf
    int ret = write_iobuf.append(iv, 12);
    // if (ret != 0) {
    //     LOG(ERROR) << "iobuf append error";
    //     return;
    // }

    //- 2. Put aad
    ret = write_iobuf.append(aad, 12);

    //- 3. Put mac
    ret = write_iobuf.append(mac, 16);

    //- 4. Put cipher_len
    ret = write_iobuf.append(&cipher_len, sizeof(int32_t));

    //- 5. Put cipher text
    ret = write_iobuf.append(msg_cipher, cipher_len);

    // Write header_buf to file
    //- TODO: header在这里似乎没有必要，因为密文的长度已经由cipher_len表示了，所以write_iobuf的长度也可以知道（IV，MAC等的长度都已知），并不需要额外的header
    sgxbutil::IOBuf header_buf;
    int32_t header_len = write_iobuf.length();
    //- Append the length of write_iobuf to header_buf
    header_buf.append(&header_len, sizeof(int32_t));
    LOG(INFO) << "length of write iobuf = " << header_len;
    
    if (sizeof(int32_t) != file->write(header_buf, 0)) {
        LOG(ERROR) << "write len failed, path: " << tmp_path;
    }
    //- Write write_iobuf to file
    if (write_iobuf.size() != file->write(write_iobuf, sizeof(int32_t))) {
        LOG(ERROR) << "write failed, path: " << tmp_path;
    }

    // sync
    if (sync) {
        if (!file->sync()) {
            LOG(ERROR) << "sync failed, path: " << tmp_path;
            return -1;
        }
    }

    // rename
    if (!_fs->rename(tmp_path, _path)) {
        LOG(ERROR) << "rename failed, old: " << tmp_path << " , new: " << _path;
        return -1;
    }
    timer.stop();
    VLOG(85) << "Func: " << __FUNCTION__ 
        << " TIME_OF pb file persistence (write and sync) = "
        << timer.m_elapsed(0.0) << " ms";

    timer.start();
    if (manager.increase_counter(*counter_id) != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Counter failed when increasing.";
    }
    timer.stop();
    
    double inc_elapse = timer.u_elapsed(0.0);
    // if (inc_elapse > 2000) {
    //     LOG(ERROR) << "Func: " << __FUNCTION__ << " _path = " << _path 
    //     << " Too Slow... TIME_OF increasing counter = "
    //     << inc_elapse/1000.0 << " ms";
    // }
    LOG(NOTICE) << "Func: " << __FUNCTION__ << " _path = " << _path 
        << " saved successfully TIME_OF increasing counter = "
        << inc_elapse << " us";
    return 0;
}

int ProtoBufFile::load(google::protobuf::Message* msg, 
                       sgxbutil::CounterID* counter_id, int flag) {
    sgxbutil::File::Error e;
    FileAdaptor* file = _fs->open(_path, O_RDONLY, NULL, &e);
    if (!file) {
        LOG(ERROR) << "open file failed, path: " << _path
                     << ": " << sgxbutil::File::ErrorToString(e);
        return -1;
    }
    std::unique_ptr<FileAdaptor, DestroyObj<FileAdaptor> > guard(file);
    LOG(INFO) << "Func: " << __FUNCTION__ << " _path = " << _path;

    sgxbutil::IOPortal read_iobuf;
    //- Retrieve the header first
    sgxbutil::IOPortal header;
    if (sizeof(int32_t) != file->read(&header, 0, sizeof(int32_t))) {
        LOG(ERROR) << "read len failed, path: " << _path;
    }
    int32_t left_len = 0;
    header.copy_to(&left_len, sizeof(int32_t));
    LOG(INFO) << "Extracted length of read iobuf = " << left_len;
    if (left_len != file->read(&read_iobuf, sizeof(int32_t), left_len)) {
        LOG(ERROR) << "read body failed, path: " << _path;
    }

    size_t offset = 0;
    //- 1. Extract iv
    unsigned char iv[12];
    int bytes_of_copied = read_iobuf.copy_to(iv, 12, offset);
    offset += bytes_of_copied;
    LOG(INFO) << "Copy " << bytes_of_copied << " Bytes to iv";

    //- 2. Extract aad
    unsigned char aad[12];
    bytes_of_copied = read_iobuf.copy_to(aad, 12, offset);
    offset += bytes_of_copied;
    //- Get counter info
    uint32_t counter_index = *((uint32_t*)aad);
    *counter_id = counter_index;
    LOG(INFO) << "Extracted counter_index = " << counter_index;
    uint64_t counter_value = *((uint64_t*)(aad+4));
    LOG(INFO) << "Extracted counter_value = " << counter_value;
    //- Rollback detection
    if (sgxbutil::GetGlobalMonoCntManager().detect_rollback(counter_index, counter_value)) {
        LOG(ERROR) << "Detect rollback attack...";
        return -1;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " _path = " << _path 
        << " loaded successfully";

    //- 3. Extract mac
    unsigned char mac[16];
    bytes_of_copied = read_iobuf.copy_to(mac, 16, offset);
    offset += bytes_of_copied;
    LOG(INFO) << "Copy " << bytes_of_copied << " Bytes to mac";

    //- 4. Extract cipher_len
    uint32_t cipher_len = 0;
    bytes_of_copied = read_iobuf.copy_to(&cipher_len, sizeof(uint32_t), offset);
    offset += bytes_of_copied;
    LOG(INFO) << "Extracted cipher_len = " << cipher_len;

    //- 5. Extract msg_cipher
    unsigned char msg_cipher[cipher_len];
    bytes_of_copied = read_iobuf.copy_to(msg_cipher, cipher_len, offset);
    LOG(INFO) << "bytes_of_copied = " << bytes_of_copied;

    //- Do decryption
    unsigned char msg_plain[cipher_len];
    unsigned char key[32];
    sgxbutil::get_sgx_seal_key_128(key);
    int decryptedtext_len = sgxbutil::gcm_decrypt(msg_cipher, cipher_len, aad, 12, mac, key, iv, 12, msg_plain);
    LOG(INFO) << "decryptedtext_len = " << decryptedtext_len;
    msg->ParseFromArray(msg_plain, cipher_len);

    return 0;
}

ProtoBufFile::ProtoBufFile(const std::string& path, FileSystemAdaptor* fs) 
    : _path(path), _fs(fs) {
    if (_fs == NULL) {
        _fs = default_file_system();
    }
}

int ProtoBufFile::save(const google::protobuf::Message* message, bool sync) {
    std::string tmp_path(_path);
    tmp_path.append(".tmp");

    sgxbutil::File::Error e;
    FileAdaptor* file = _fs->open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, NULL, &e);
    if (!file) {
        LOG(WARNING) << "open file failed, path: " << _path
                     << ": " << sgxbutil::File::ErrorToString(e);
        return -1;
    }
    std::unique_ptr<FileAdaptor, DestroyObj<FileAdaptor> > guard(file);

    // serialize msg
    sgxbutil::IOBuf header_buf;
    sgxbutil::IOBuf msg_buf;
    sgxbutil::IOBufAsZeroCopyOutputStream msg_wrapper(&msg_buf);
    message->SerializeToZeroCopyStream(&msg_wrapper);

    // write len
    int32_t header_len = sgxbutil::HostToNet32(msg_buf.length());
    header_buf.append(&header_len, sizeof(int32_t));
    if (sizeof(int32_t) != file->write(header_buf, 0)) {
        LOG(WARNING) << "write len failed, path: " << tmp_path;
        return -1;
    }

    ssize_t len = msg_buf.size();
    if (len != file->write(msg_buf, sizeof(int32_t))) {
        LOG(WARNING) << "write failed, path: " << tmp_path;
        return -1;
    }

    // sync
    if (sync) {
        if (!file->sync()) {
            LOG(WARNING) << "sync failed, path: " << tmp_path;
            return -1;
        }
    }

    // rename
    if (!_fs->rename(tmp_path, _path)) {
        LOG(WARNING) << "rename failed, old: " << tmp_path << " , new: " << _path;
        return -1;
    }
    return 0;
}

int ProtoBufFile::load(google::protobuf::Message* message) {
    sgxbutil::File::Error e;
    FileAdaptor* file = _fs->open(_path, O_RDONLY, NULL, &e);
    if (!file) {
        LOG(WARNING) << "open file failed, path: " << _path
                     << ": " << sgxbutil::File::ErrorToString(e);
        return -1;
    }

    std::unique_ptr<FileAdaptor, DestroyObj<FileAdaptor> > guard(file);

    // len
    sgxbutil::IOPortal header_buf;
    if (sizeof(int32_t) != file->read(&header_buf, 0, sizeof(int32_t))) {
        LOG(WARNING) << "read len failed, path: " << _path;
        return -1;
    }
    int32_t len = 0;
    header_buf.copy_to(&len, sizeof(int32_t));
    int32_t left_len = sgxbutil::NetToHost32(len);

    // read protobuf data
    sgxbutil::IOPortal msg_buf;
    if (left_len != file->read(&msg_buf, sizeof(int32_t), left_len)) {
        LOG(WARNING) << "read body failed, path: " << _path;
        return -1;
    }

    // parse msg
    sgxbutil::IOBufAsZeroCopyInputStream msg_wrapper(msg_buf);
    message->ParseFromZeroCopyStream(&msg_wrapper);

    return 0;
}

}
