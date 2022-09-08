#include "braft/log_enc2.h"

#include "google/gflags/gflags.h"
#include "sgxbutil/files/dir_reader_posix.h"            // sgxbutil::DirReaderPosix
#include "sgxbutil/file_util.h"                         // sgxbutil::CreateDirectory
#include "sgxbutil/string_printf.h"                     // sgxbutil::string_appendf
#include "sgxbutil/time.h"
#include "sgxbutil/raw_pack.h"                          // sgxbutil::RawPacker
#include "sgxbutil/fd_utility.h"                        // sgxbutil::make_close_on_exec
#include "brpc/reloadable_flags.h"             // 

#include "braft/local_storage.pb.h"
#include "braft/log_entry.h"
#include "braft/protobuf_file.h"
#include "braft/util.h"
#include "braft/fsync.h"
#include "sgxbutil/state_cont/openssl_utils.h"
#define BRAFT_SEGMENT_OPEN_NAME "log"
#define BRAFT_SEGMENT_CLOSED_PATTERN "log_%020" PRId64 "_%020" PRId64
#define BRAFT_SEGMENT_META_FILE  "log_meta"

namespace braft {

DECLARE_bool(raft_trace_append_entry_latency);

extern int ftruncate_uninterrupted(int fd, off_t length);

//- Format of Log Entry Header
// | ---------------- IV (12B) -------------------  |
// | log_index (8B) | log_term (8B) | log_type (1B) |
// | -------- MAC (16B) | log_length (4B) --------- |
//- Note that log_index, log_term and log_type are AAD in AES-GCM
const static size_t ENC2_ENTRY_HEADER_SIZE = 49;

struct EncryptedSegmentTest::EntryHeader {
    int64_t index;
    int64_t term;
    int type;
    uint32_t data_len;
};

std::ostream& operator<<(std::ostream& os, const EncryptedSegmentTest::EntryHeader& h) {
    os << "{term=" << h.term << ", type=" << h.type << ", data_len="
       << h.data_len << '}';
    return os;
}

int EncryptedSegmentTest::create() {
    if (!_is_open) {
        CHECK(false) << "Create on a closed segment at first_index=" 
                     << _first_index << " in " << _path;
        return -1;
    }

    std::string path(_path);
    path.append("/" BRAFT_SEGMENT_OPEN_NAME);
    _fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    LOG(INFO) << "Func: " << __FUNCTION__ << " _fd = " << _fd;
    if (_fd >= 0) {
        sgxbutil::make_close_on_exec(_fd);
    }
    LOG_IF(INFO, _fd >= 0) << "Created new segment `" << path 
                           << "' with fd=" << _fd ;
    return _fd >= 0 ? 0 : -1;
}

int EncryptedSegmentTest::_load_entry(off_t offset, EntryHeader* head, sgxbutil::IOBuf* data,
                         size_t size_hint) const {
    if (size_hint > ENC2_ENTRY_HEADER_SIZE) {
        return _load_whole_entry(offset, head, data, size_hint);
    }
    sgxbutil::IOPortal read_iobuf;
    const ssize_t n = file_pread(&read_iobuf, _fd, offset, ENC2_ENTRY_HEADER_SIZE);    
    if (n != (ssize_t)ENC2_ENTRY_HEADER_SIZE) {
        return n < 0 ? -1 : 1;
    }    

    EntryHeader tmp;
    unsigned char iv[12];
    unsigned char mac[16];
    unsigned char aad[17];
    size_t cipher_len = _extract_log_entry_header(read_iobuf, iv, aad, mac, &tmp);
    if (cipher_len <= 0) {    
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Extract cipher_len failed.";
        return -1;
    }

    sgxbutil::IOPortal log_data_iobuf;
    offset += n;
    const ssize_t n_bytes = file_pread(&log_data_iobuf, _fd, offset, cipher_len);
    if (n_bytes != (ssize_t)cipher_len) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " file_pread error, n_bytes = " << n_bytes;
        return n_bytes < 0 ? -1 : 1;
    }
    unsigned char cipher_data[cipher_len];
    unsigned char plain_data[cipher_len];
    unsigned char key[32];
    sgxbutil::get_sgx_seal_key_128(key);
    log_data_iobuf.copy_to(cipher_data, cipher_len);
    int decryptedtext_len = sgxbutil::gcm_decrypt(cipher_data, cipher_len, aad, 17, mac, key, iv, 12, plain_data);
    //- Check results
    if (decryptedtext_len != cipher_len) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Log decryption failed";
        return -1;
    }   

    if (head != NULL) {
        *head = tmp;
    }
    
    if (data != NULL) {
        //- Construct iobuf to return
        sgxbutil::IOBuf ret_buf;
        ret_buf.append(plain_data, cipher_len);
        data->swap(ret_buf);
    }
    return 0;
}

int EncryptedSegmentTest::_extract_log_entry_header(sgxbutil::IOBuf read_iobuf, unsigned char* iv, unsigned char* aad, unsigned char* mac, EntryHeader* head) const {
    size_t buf_offset = 0;
    //- 1. Extract iv
    int bytes_of_copied = read_iobuf.copy_to(iv, 12, buf_offset);
    buf_offset += bytes_of_copied;
    LOG(INFO) << "Copy " << bytes_of_copied << " Bytes to iv";

    //- 2. Extract aad
    bytes_of_copied = read_iobuf.copy_to(aad, 17, buf_offset);
    buf_offset += bytes_of_copied;
    //- For debugging
    int64_t log_index = *((int64_t*)aad);
    LOG(INFO) << "Extracted log_index = " << log_index;
    int64_t log_term = *((int64_t*)(aad+8));
    LOG(INFO) << "Extracted log_term = " << log_term;
    int log_type = aad[16];
    LOG(INFO) << "Extracted log_type = " << log_type;

    //- 3. Extract mac
    bytes_of_copied = read_iobuf.copy_to(mac, 16, buf_offset);
    buf_offset += bytes_of_copied;
    LOG(INFO) << "Copy " << bytes_of_copied << " Bytes to mac";

    //- 4. Extract cipher_len
    uint32_t cipher_len = 0;
    bytes_of_copied = read_iobuf.copy_to(&cipher_len, sizeof(uint32_t), buf_offset);
    buf_offset += bytes_of_copied;
    LOG(INFO) << "Extracted cipher_len = " << cipher_len;

    head->index = *((int64_t*)aad);
    head->term = *((int64_t*)(aad+8));
    head->type = aad[16];
    head->data_len = cipher_len;
    return cipher_len;
}

int EncryptedSegmentTest::_get_meta(int64_t index, LogMeta* meta) const {
    BAIDU_SCOPED_LOCK(_mutex);
    if (index > _last_index.load(sgxbutil::memory_order_relaxed) 
                    || index < _first_index) {
        // out of range
        BRAFT_VLOG << "_last_index=" << _last_index.load(sgxbutil::memory_order_relaxed)
                  << " _first_index=" << _first_index;
        return -1;
    } else if (_last_index == _first_index - 1) {
        BRAFT_VLOG << "_last_index=" << _last_index.load(sgxbutil::memory_order_relaxed)
                  << " _first_index=" << _first_index;
        // empty
        return -1;
    }
    int64_t meta_index = index - _first_index;
    int64_t entry_cursor = _offset_and_term[meta_index].first;
    int64_t next_cursor = (index < _last_index.load(sgxbutil::memory_order_relaxed))
                          ? _offset_and_term[meta_index + 1].first : _bytes;
    DCHECK_LT(entry_cursor, next_cursor);
    meta->offset = entry_cursor;
    meta->term = _offset_and_term[meta_index].second;
    meta->length = next_cursor - entry_cursor;
    return 0;
}

int EncryptedSegmentTest::_load_whole_entry(off_t offset, EntryHeader* head, sgxbutil::IOBuf* data,
                         size_t size_hint) const {

    sgxbutil::IOPortal read_iobuf;
    const ssize_t n = file_pread(&read_iobuf, _fd, offset, size_hint);
    if (n != (ssize_t)size_hint) {
        return n < 0 ? -1 : 1;
    }

    EntryHeader tmp;
    unsigned char iv[12];
    unsigned char mac[16];
    unsigned char aad[17];
    size_t cipher_len = _extract_log_entry_header(read_iobuf, iv, aad, mac, &tmp);
    if (cipher_len <= 0) {    
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Extract cipher_len failed.";
        return -1;
    }

    //- Extract msg_cipher
    unsigned char msg_cipher[cipher_len];
    int bytes_of_copied = read_iobuf.copy_to(msg_cipher, cipher_len, ENC2_ENTRY_HEADER_SIZE);
    LOG(INFO) << "bytes_of_copied = " << bytes_of_copied;

    //- Do decryption
    unsigned char msg_plain[cipher_len];
    unsigned char key[32];
    sgxbutil::get_sgx_seal_key_128(key);
    int decryptedtext_len = sgxbutil::gcm_decrypt(msg_cipher, cipher_len, aad, 17, mac, key, iv, 12, msg_plain);
    //- Check results
    if (decryptedtext_len != cipher_len) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Log decryption failed";
        return -1;
    }

    if (head != NULL) {
        *head = tmp;
    }
    
    if (data != NULL) {
        //- Construct iobuf to return
        sgxbutil::IOBuf ret_buf;
        ret_buf.append(msg_plain, cipher_len);
        data->swap(ret_buf);
    }
    return 0;
}

int EncryptedSegmentTest::load(ConfigurationManager* configuration_manager) {
    VLOG(79) << "Func: " << __FUNCTION__ << " Enter load";
    int ret = 0;

    std::string path(_path);
    path.append("/" BRAFT_SEGMENT_OPEN_NAME);
    // create fd
    _fd = ::open(path.c_str(), O_RDWR);
    LOG(INFO) << "Func: " << __FUNCTION__ << " _fd = " << _fd << " path = " << path;
    if (_fd < 0) {
        LOG(ERROR) << "Fail to open " << path << ", " << berror();
        return -1;
    }
    sgxbutil::make_close_on_exec(_fd);

    // get file size
    struct stat st_buf;
    if (fstat(_fd, &st_buf) != 0) {
        LOG(ERROR) << "Fail to get the stat of " << path << ", " << berror();
        ::close(_fd);
        _fd = -1;
        return -1;
    }

    LOG(INFO) << "Func: " << __FUNCTION__ << " first_index = " << _first_index << " last_index = " << _last_index;

    // load entry index
    //- Total size of this file, in bytes
    int64_t file_size = st_buf.st_size;
    int64_t entry_off = 0;    
    //- When check_start, start checking log consistency
    bool check_start = false;
    int idx = 0;
    while (entry_off < file_size) {
        EntryHeader header;
        const int rc = _load_entry(entry_off, &header, NULL, ENC2_ENTRY_HEADER_SIZE);
        if (rc > 0) {
            // The last log was not completely written, which should be truncated
            break;
        }
        if (rc < 0) {
            ret = rc;
            break;
        }
        // rc == 0
        //- Check index consistency
        //- If header.index equals to _first_index, we can start checking
        if (!check_start && (header.index == _first_index) ) {
            LOG(INFO) << "Func: " << __FUNCTION__ << " header.index = " << header.index;
            check_start = true;
            idx = 0;
        }
        if (check_start) {
            if (header.index != _first_index + idx) {
                LOG(ERROR) << "Func: " << __FUNCTION__ << " Consistency check failed.";
                ret = -1;
                break;
            }
            idx++;
        }

        const int64_t skip_len = ENC2_ENTRY_HEADER_SIZE + header.data_len;
        if (entry_off + skip_len > file_size) {
            // The last log was not completely written and it should be
            // truncated
            break;
        }
        if (header.type == ENTRY_TYPE_CONFIGURATION) {
            sgxbutil::IOBuf data;
            // Header will be parsed again but it's fine as configuration
            // changing is rare
            if (_load_entry(entry_off, NULL, &data, skip_len) != 0) {
                break;
            }
            sgxscoped_refptr<LogEntry> entry = new LogEntry();
            entry->id.index = header.index;
            entry->id.term = header.term;
            sgxbutil::Status status = parse_configuration_meta(data, entry);
            if (status.ok()) {
                ConfigurationEntry conf_entry(*entry);
                configuration_manager->add(conf_entry); 
            } else {
                LOG(ERROR) << "fail to parse configuration meta, path: " << _path
                    << " entry_off " << entry_off;
                ret = -1;
                break;
            }
        }
        _offset_and_term.push_back(std::make_pair(entry_off, header.term));
        entry_off += skip_len;
    }

    if (ret != 0) {
        return ret;
    }

    //- Check first log index
    if (!check_start) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " check_start faild.";
        return -1;
    }

    //- Check last log index
    int64_t actual_last_index = _first_index + idx - 1;    
    const int64_t last_index = _last_index.load(sgxbutil::memory_order_relaxed);
    if (actual_last_index != last_index) {
        LOG(ERROR) << "Func: " << __FUNCTION__
                   << " Log inconsistency, expected_last_index = " 
                   << last_index << " actual_last_index = " << actual_last_index;
        return -1;
    }

    // truncate last uncompleted entry
    if (entry_off != file_size) {
        LOG(INFO) << "truncate last uncompleted write entry, path: " << _path
            << " first_index: " << _first_index << " old_size: " << file_size << " new_size: " << entry_off;
        ret = ftruncate_uninterrupted(_fd, entry_off);
    }

    // seek to end, for opening segment
    ::lseek(_fd, entry_off, SEEK_SET);

    _bytes = entry_off;
    return ret;
}

int EncryptedSegmentTest::append(const LogEntry* entry) {

    if (BAIDU_UNLIKELY(!entry || !_is_open)) {
        return EINVAL;
    } else if (entry->id.index != 
                    _last_index.load(sgxbutil::memory_order_consume) + 1) {
        CHECK(false) << "entry->index=" << entry->id.index
                  << " _last_index=" << _last_index
                  << " _first_index=" << _first_index;
        return ERANGE;
    }

    sgxbutil::IOBuf data;
    switch (entry->type) {
    case ENTRY_TYPE_DATA:
        data.append(entry->data);
        break;
    case ENTRY_TYPE_NO_OP:
        break;
    case ENTRY_TYPE_CONFIGURATION: 
        {
            sgxbutil::Status status = serialize_configuration_meta(entry, data);
            if (!status.ok()) {
                LOG(ERROR) << "Fail to serialize ConfigurationPBMeta, path: " 
                           << _path;
                return -1; 
            }
        }
        break;
    default:
        LOG(FATAL) << "unknow entry type: " << entry->type
                   << ", path: " << _path;
        return -1;
    }
    CHECK_LE(data.length(), 1ul << 56ul);
    // sgxbutil::Timer timer;   
    // timer.start();
    //- Buffer for plain and cipher data
    int data_bytes = data.length();
    unsigned char data_plain[data_bytes];
    unsigned char data_cipher[data_bytes];
    data.copy_to(data_plain, data_bytes, 0);
    //- Buffer for iv, key, mac
    unsigned char iv[12];
    sgxbutil::get_init_vector(iv, sizeof(iv));
    unsigned char key[32];
    sgxbutil::get_sgx_seal_key_128(key);
    unsigned char mac[16];
    //- Construct AAD
    unsigned char aad[17];
    int64_t log_index = entry->id.index;
    int64_t log_term = entry->id.term;
    memcpy(aad, (unsigned char*)&log_index, sizeof(int64_t));
    memcpy(aad+sizeof(int64_t), (unsigned char*)&log_term, sizeof(int64_t));
    aad[16] = entry->type;
    //- Do encryption
    LOG(NOTICE) << "Func: " << __FUNCTION__ << " gcm_encrypt length = "
        << data_bytes << " bytes" << " log type = " << entry->type;
    // int32_t cipher_len = data_bytes;
    int32_t cipher_len = sgxbutil::gcm_encrypt(data_plain, data_bytes, aad, 17, key, iv, 12, data_cipher, mac);
    // timer.stop();
    // VLOG(85) << "Func: " << __FUNCTION__ << " TIME_OF log encryption = "
    //     << timer.m_elapsed(0.0) << " ms";
    //- Then transform data_cipher to iobuf
    sgxbutil::IOBuf data_cipher_out;
    data_cipher_out.append(data_cipher, cipher_len);
    LOG(INFO) << "Log cipher_len = " << cipher_len;

    //- Construct log entry header (totally 49 Bytes)
    sgxbutil::IOBuf log_entry_header;
    log_entry_header.append(iv, 12);
    log_entry_header.append(aad, 17);
    log_entry_header.append(mac, 16);
    log_entry_header.append(&cipher_len, 4);

    const size_t to_write = log_entry_header.length() + data_cipher_out.length();
    sgxbutil::IOBuf* pieces[2] = { &log_entry_header, &data_cipher_out };
    size_t start = 0;
    ssize_t written = 0;
    // timer.start();
    while (written < (ssize_t)to_write) {
        //- cut_multiple_into_file_descriptor func finally writes data_cipher_out to disk, through the file descriptor _fd
        const ssize_t n = sgxbutil::IOBuf::cut_multiple_into_file_descriptor(
                _fd, pieces + start, ARRAY_SIZE(pieces) - start);
        if (n < 0) {
            LOG(ERROR) << "Fail to write to fd=" << _fd 
                       << ", path: " << _path << berror();
            return -1;
        }
        written += n;
        //- Update variable start
        for (;start < ARRAY_SIZE(pieces) && pieces[start]->empty(); ++start) {}
    }
    // timer.stop();
    // VLOG(85) << "Func: " << __FUNCTION__ << " TIME_OF log persistence #1: write = "
    //     << timer.m_elapsed(0.0) << " ms";
    BAIDU_SCOPED_LOCK(_mutex);
    _offset_and_term.push_back(std::make_pair(_bytes, entry->id.term));
    _last_index.fetch_add(1, sgxbutil::memory_order_relaxed);
    _bytes += to_write;

    return 0;
}

int EncryptedSegmentTest::sync(bool will_sync) {
    if (_last_index > _first_index) {
        //CHECK(_is_open);
        if (FLAGS_raft_sync && will_sync) {
            // LOG(INFO) << "Func: " << __FUNCTION__ << " will sync data";
            return raft_fsync(_fd);
        } else {
            return 0;
        }
    } else {
        return 0;
    }
}

LogEntry* EncryptedSegmentTest::get(const int64_t index) const {

    LogMeta meta;
    if (_get_meta(index, &meta) != 0) {
        return NULL;
    }

    bool ok = true;
    LogEntry* entry = NULL;
    do {
        ConfigurationPBMeta configuration_meta;
        EntryHeader header;
        sgxbutil::IOBuf data;
        if (_load_entry(meta.offset, &header, &data, 
                        meta.length) != 0) {
            ok = false;
            break;
        }
        CHECK_EQ(meta.term, header.term);
        entry = new LogEntry();
        entry->AddRef();
        switch (header.type) {
        case ENTRY_TYPE_DATA:
            entry->data.swap(data);
            break;
        case ENTRY_TYPE_NO_OP:
            CHECK(data.empty()) << "Data of NO_OP must be empty";
            break;
        case ENTRY_TYPE_CONFIGURATION:
            {
                sgxbutil::Status status = parse_configuration_meta(data, entry); 
                if (!status.ok()) {
                    LOG(WARNING) << "Fail to parse ConfigurationPBMeta, path: "
                                 << _path;
                    ok = false;
                    break;
                }
            }
            break;
        default:
            CHECK(false) << "Unknown entry type, path: " << _path;
            break;
        }

        if (!ok) { 
            break;
        }
        entry->id.index = index;
        entry->id.term = header.term;
        entry->type = (EntryType)header.type;
    } while (0);

    if (!ok && entry != NULL) {
        entry->Release();
        entry = NULL;
    }
    return entry;
}

int64_t EncryptedSegmentTest::get_term(const int64_t index) const {
    LogMeta meta;
    if (_get_meta(index, &meta) != 0) {
        return 0;
    }
    return meta.term;
}


std::string EncryptedSegmentTest::file_name() {
    return std::string(BRAFT_SEGMENT_OPEN_NAME);
}

static void* run_unlink(void* arg) {
    std::string* file_path = (std::string*) arg;
    sgxbutil::Timer timer;
    timer.start();
    int ret = ::unlink(file_path->c_str());
    timer.stop();
    BRAFT_VLOG << "unlink " << *file_path << " ret " << ret << " time: " << timer.u_elapsed();
    delete file_path;

    return NULL;
}

int EncryptedSegmentTest::unlink() {
    int ret = 0;
    do {
        std::string path(_path);
        if (_is_open) {
            path.append("/" BRAFT_SEGMENT_OPEN_NAME);
        } else {//- TO BE DELETED
            sgxbutil::string_appendf(&path, "/" BRAFT_SEGMENT_CLOSED_PATTERN,
                                _first_index, _last_index.load());
        }

        std::string tmp_path(path);
        tmp_path.append(".tmp");
        ret = ::rename(path.c_str(), tmp_path.c_str());
        if (ret != 0) {
            PLOG(ERROR) << "Fail to rename " << path << " to " << tmp_path;
            break;
        }

        // start bthread to unlink
        // TODO unlink follow control
        std::string* file_path = new std::string(tmp_path);
        bthread_t tid;
        if (bthread_start_background(&tid, &BTHREAD_ATTR_NORMAL, run_unlink, file_path) != 0) {
            run_unlink(file_path);
        }

        LOG(INFO) << "Unlinked segment `" << path << '\'';
    } while (0);

    return ret;
}


int EncryptedSegmentTest::truncate_prefix(const int64_t first_index_kept) {
    if (first_index_kept <= _first_index) {
        return 0;
    }
    std::unique_lock<raft_mutex_t> lck(_mutex);
    //- Caculate how many bytes should be removed
    int index_cnt = first_index_kept - _first_index;
    int remove_bytes = _offset_and_term[index_cnt].first;
    LOG(INFO) << "Func: " << __FUNCTION__ << " remove_bytes = " << remove_bytes;
    
    //- Buffer
    char buff[1024];
    int len = 0;
    int total_size = 0;
    //- Basic logic: 1-4
    //- 1. Rename log file to that with tmp suffix
    std::string path(_path);
    path.append("/" BRAFT_SEGMENT_OPEN_NAME);
    std::string path_new(_path);
    path_new.append("/" BRAFT_SEGMENT_OPEN_NAME ".tmp");
    int ret = ::rename(path.c_str(), path_new.c_str());
    if (ret != 0) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " Rename log file failed.";
    }

    //- 2. Create a new log file
    int new_fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);

    //- 3. Copy needed content from tmp file (to be truncated) to new file 
    ::lseek(_fd, remove_bytes, SEEK_SET);
    len = read(_fd, buff, 1024);
    while(len) {
        LOG(INFO) << "Func: " << __FUNCTION__ << " read_len = " << len;
        total_size += len;
		write(new_fd, buff, len);
        len = read(_fd, buff, 1024);
	}

    //- 4. Delete tmp file
    ::close(_fd);
    ::unlink(path_new.c_str());

    //- 5. Update data
    _fd = new_fd;
    CHECK(total_size == (_bytes - remove_bytes)) << " Func: " << __FUNCTION__ << " total_size error.";
    _bytes -= remove_bytes;
    ::lseek(_fd, total_size, SEEK_SET);

    //- Remove useless items in offset-term vector
    for (int i = 0; i < index_cnt; i++) {
        _offset_and_term.erase(_offset_and_term.begin());
    }
    //- Revise the value of offset
    for (auto it = _offset_and_term.begin(); it != _offset_and_term.end(); it++) {
        it->first -= remove_bytes;
    }

    _first_index = first_index_kept;
    return 0;
}

int EncryptedSegmentTest::truncate_suffix(const int64_t last_index_kept) {
    int64_t truncate_size = 0;
    int64_t first_truncate_in_offset = 0;
    std::unique_lock<raft_mutex_t> lck(_mutex);
    if (last_index_kept >= _last_index) {
        return 0;
    }
    first_truncate_in_offset = last_index_kept + 1 - _first_index;
    truncate_size = _offset_and_term[first_truncate_in_offset].first;
    BRAFT_VLOG << "Truncating " << _path << " first_index: " << _first_index
              << " last_index from " << _last_index << " to " << last_index_kept
              << " truncate size to " << truncate_size;
    lck.unlock();

    // truncate fd
    int ret = ftruncate_uninterrupted(_fd, truncate_size);
    if (ret < 0) {
        return ret;
    }

    // seek fd
    off_t ret_off = ::lseek(_fd, truncate_size, SEEK_SET);
    if (ret_off < 0) {
        PLOG(ERROR) << "Fail to lseek fd=" << _fd << " to size=" << truncate_size
                    << " path: " << _path;
        return -1;
    }

    lck.lock();
    // update memory var
    _offset_and_term.resize(first_truncate_in_offset);
    _last_index.store(last_index_kept, sgxbutil::memory_order_relaxed);
    _bytes = truncate_size;
    return ret;
}

int EncryptedSegmentTestLogStorage::init(ConfigurationManager* configuration_manager) {
    sgxbutil::FilePath dir_path(_path);
    sgxbutil::File::Error e;
    if (!sgxbutil::CreateDirectoryAndGetError(
                dir_path, &e, FLAGS_raft_create_parent_directories)) {
        LOG(ERROR) << "Fail to create " << dir_path.value() << " : " << e;
        return -1;
    }

    int ret = 0;
    bool is_empty = false;
    do {
        ret = load_meta();
        if (ret != 0 && errno == ENOENT) {
            LOG(WARNING) << _path << " is empty";
            is_empty = true;
            _first_log_index.store(1);
            _last_log_index.store(0);
            //- Indicate empty log
            //- TODO: We don't need to save meta if the log is empty.
            // ret = save_meta(1,0);
        } else if (ret != 0) {
            break;
        }

        ret = list_segments(is_empty);
        if (ret != 0) {
            break;
        }

        ret = load_segments(configuration_manager);
        if (ret != 0) {
            break;
        }
    } while (0);

    return ret;
}

int64_t EncryptedSegmentTestLogStorage::last_log_index() {
    return _last_log_index.load(sgxbutil::memory_order_acquire);
}

int EncryptedSegmentTestLogStorage::append_entries(const std::vector<LogEntry*>& entries, IOMetric* metric) {
    if (entries.empty()) {
        return 0;
    }
    if (_last_log_index.load(sgxbutil::memory_order_relaxed) + 1
            != entries.front()->id.index) {
        LOG(FATAL) << "There's gap between appending entries and _last_log_index"
                   << " path: " << _path;
        return -1;
    }
    sgxscoped_refptr<EncryptedSegmentTest> last_segment = NULL;
    int64_t now = 0;
    int64_t delta_time_us = 0;
    for (size_t i = 0; i < entries.size(); i++) {
        now = sgxbutil::cpuwide_time_us();
        LogEntry* entry = entries[i];
        
        //- Obtain the segment that opens now
        sgxscoped_refptr<EncryptedSegmentTest> segment = open_segment();
        if (FLAGS_raft_trace_append_entry_latency && metric) {
            delta_time_us = sgxbutil::cpuwide_time_us() - now;
            metric->open_segment_time_us += delta_time_us;
        }
        if (NULL == segment) {
            return i;
        }
        //- Call EncryptedSegmentTest::append func to conduct appending
        //- Only append one log entry when calling this func
        int ret = segment->append(entry);
        if (0 != ret) {
            return i;
        }
        if (FLAGS_raft_trace_append_entry_latency && metric) {
            delta_time_us = sgxbutil::cpuwide_time_us() - now;
            metric->append_entry_time_us += delta_time_us;
        }
        _last_log_index.fetch_add(1, sgxbutil::memory_order_release);        
        //- When append is finished, update log_meta
        //- Move meata saving outside the "for" loop to achieve batch processing
        // save_meta(first_log_index(), last_log_index());
        last_segment = segment;
    }
    now = sgxbutil::cpuwide_time_us();
    save_meta(first_log_index(), last_log_index());
    //- TODO: Shall we put sync before meta saving?
    // sgxbutil::Timer timer;
    // timer.start();
    //- In SGX-Raft, we have rollback prevention and thus sync is not needed
    last_segment->sync(_enable_sync);
    // timer.stop();
    // VLOG(85) << "Func: " << __FUNCTION__ << " TIME_OF log persistence #2: sync = "
    //     << timer.m_elapsed(0.0) << " ms" << " entries.size = " << entries.size();
    if (FLAGS_raft_trace_append_entry_latency && metric) {
        delta_time_us = sgxbutil::cpuwide_time_us() - now;
        metric->sync_segment_time_us += delta_time_us;
    }
    return entries.size();
}

int EncryptedSegmentTestLogStorage::append_entry(const LogEntry* entry) {
    sgxscoped_refptr<EncryptedSegmentTest> segment = open_segment();
    if (NULL == segment) {
        return EIO;
    }
    int ret = segment->append(entry);
    if (ret != 0 && ret != EEXIST) {
        return ret;
    }
    if (EEXIST == ret && entry->id.term != get_term(entry->id.index)) {
        return EINVAL;
    }
    _last_log_index.fetch_add(1, sgxbutil::memory_order_release);

    return segment->sync(_enable_sync);
}

LogEntry* EncryptedSegmentTestLogStorage::get_entry(const int64_t index) {
    sgxscoped_refptr<EncryptedSegmentTest> ptr;
    if (get_segment(index, &ptr) != 0) {
        return NULL;
    }
    return ptr->get(index);
}

int64_t EncryptedSegmentTestLogStorage::get_term(const int64_t index) {
    sgxscoped_refptr<EncryptedSegmentTest> ptr;
    if (get_segment(index, &ptr) != 0) {
        return 0;
    }
    return ptr->get_term(index);
}

void EncryptedSegmentTestLogStorage::pop_segments(
        const int64_t first_index_kept,
        std::vector<sgxscoped_refptr<EncryptedSegmentTest> >* popped) {
    popped->clear();
    popped->reserve(32);
    BAIDU_SCOPED_LOCK(_mutex);
    _first_log_index.store(first_index_kept, sgxbutil::memory_order_release);
    //- TO BE DELETED
    for (SegmentMap::iterator it = _segments.begin(); it != _segments.end();) {
        sgxscoped_refptr<EncryptedSegmentTest>& segment = it->second;
        if (segment->last_index() < first_index_kept) {
            popped->push_back(segment);
            _segments.erase(it++);
        } else {
            return;
        }
    }

    if (_open_segment) {
        if (_open_segment->last_index() < first_index_kept) {
            popped->push_back(_open_segment);
            _open_segment = NULL;
            // _log_storage is empty
            _last_log_index.store(first_index_kept - 1);
        } else {
            CHECK(_open_segment->first_index() <= first_index_kept);
        }
    } else {
        // _log_storage is empty
        _last_log_index.store(first_index_kept - 1);
    }
}

int EncryptedSegmentTestLogStorage::truncate_prefix(const int64_t first_index_kept) {
    //- In sgx-braft, only one segment (i.e., the _open_segment) is used
    if (_open_segment == NULL) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find open segment.";
        return -1;
    }
    LOG(INFO) << "Func: " << __FUNCTION__;
    // segment files
    if (_first_log_index.load(sgxbutil::memory_order_acquire) >= first_index_kept) {
      BRAFT_VLOG << "Nothing is going to happen since _first_log_index=" 
                     << _first_log_index.load(sgxbutil::memory_order_relaxed)
                     << " >= first_index_kept="
                     << first_index_kept;
        return 0;
    }
    
    // NOTE: truncate_prefix is not important, as it has nothing to do with 
    // consensus. We try to save meta on the disk first to make sure even if
    // the deleting fails or the process crashes (which is unlikely to happen).
    // The new process would see the latest `first_log_index'
    LOG(INFO) << "Func: " << __FUNCTION__ << " EncryptedSegmentTestLogStorage calling save meta, first_index = " << first_index_kept;
    _first_log_index.store(first_index_kept, sgxbutil::memory_order_relaxed);
    save_meta(first_index_kept, last_log_index());
    
    int ret = _open_segment->truncate_prefix(first_index_kept);
    if (ret != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " _open_segment->truncate_prefix failed.";
        return -1;
    }
    
    return 0;
}


int EncryptedSegmentTestLogStorage::truncate_suffix(const int64_t last_index_kept) {
    //- In sgx-braft, only one segment (i.e., the _open_segment) is used
    if (_open_segment == NULL) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " Can't find open segment.";
        return -1;
    }
    int ret = _open_segment->truncate_suffix(last_index_kept);
    if (ret != 0) {
        LOG(ERROR) << "Func: " << __FUNCTION__ << " _open_segment->truncate_suffix failed.";
        return -1;
    }
    _last_log_index.store(last_index_kept, sgxbutil::memory_order_relaxed);
    //- After truncation, save meta
    save_meta(first_log_index(), last_index_kept);
    return ret;
}

int EncryptedSegmentTestLogStorage::reset(const int64_t next_log_index) {
    if (next_log_index <= 0) {
        LOG(ERROR) << "Invalid next_log_index=" << next_log_index
                   << " path: " << _path;
        return EINVAL;
    }
    std::vector<sgxscoped_refptr<EncryptedSegmentTest> > popped;
    std::unique_lock<raft_mutex_t> lck(_mutex);
    popped.reserve(_segments.size());
    for (SegmentMap::const_iterator 
            it = _segments.begin(); it != _segments.end(); ++it) {
        popped.push_back(it->second);
    }
    _segments.clear();
    if (_open_segment) {
        popped.push_back(_open_segment);
        _open_segment = NULL;
    }
    _first_log_index.store(next_log_index, sgxbutil::memory_order_relaxed);
    _last_log_index.store(next_log_index - 1, sgxbutil::memory_order_relaxed);
    lck.unlock();
    // NOTE: see the comments in truncate_prefix
    //- TODO: What's last index?
    if (save_meta(next_log_index, -1) != 0) {
        PLOG(ERROR) << "Fail to save meta, path: " << _path;
        return -1;
    }
    for (size_t i = 0; i < popped.size(); ++i) {
        popped[i]->unlink();
        popped[i] = NULL;
    }
    return 0;
}

int EncryptedSegmentTestLogStorage::list_segments(bool is_empty) {
    sgxbutil::DirReaderPosix dir_reader(_path.c_str());
    if (!dir_reader.IsValid()) {
        LOG(WARNING) << "directory reader failed, maybe NOEXIST or PERMISSION."
                     << " path: " << _path;
        return -1;
    }

    //- Only focus on log data here, since log meta is read before.
    while (dir_reader.Next()) {
        if (strcmp(dir_reader.name(), BRAFT_SEGMENT_OPEN_NAME) == 0) {
            //- Detect log data
            //- This log data should be discarded
            if (is_empty) {
                std::string segment_path(_path);
                segment_path.append("/");
                segment_path.append(dir_reader.name());
                ::unlink(segment_path.c_str());
                
            } 
            //- Restore logs from the log data, later we will check consistency in EncryptedSegmentTest::load
            else {
                //- The first/last index is extracted from log meta to 
                //- prevent rollback attack
                if (!_open_segment) {
                    _open_segment = new EncryptedSegmentTest(_path, first_log_index(), last_log_index());
                } else {
                    LOG(WARNING) << "open segment conflict, path: " << _path;
                    return -1;
                }    
            }
            break;
        }
    }    
    return 0;
}

int EncryptedSegmentTestLogStorage::load_segments(ConfigurationManager* configuration_manager) {
    int ret = 0;
    // open segment
    if (_open_segment) {
        LOG(INFO) << "load open segment, path: " << _path
            << " first_index: " << _open_segment->first_index();
        ret = _open_segment->load(configuration_manager);
        if (ret != 0) {
            return ret;
        }
        //- Once loaded successfully, 
        //- fist/last_index in EncryptedSegmentTestLogStorage and _open_segment are the same.
    }
    //- TODO: Why?
    if (_last_log_index == 0) {
        _last_log_index = _first_log_index - 1;
    }
    return 0;
}

int EncryptedSegmentTestLogStorage::save_meta(const int64_t first_log_index, 
                                 const int64_t last_log_index) {
    LOG(INFO) << "Func: " << __FUNCTION__;
    sgxbutil::Timer timer;
    timer.start();

    std::string meta_path(_path);
    meta_path.append("/" BRAFT_SEGMENT_META_FILE);

    LogPBMeta meta;
    meta.set_first_log_index(first_log_index);
    meta.set_last_log_index(last_log_index);
    ProtoBufFile pb_file(meta_path);

    int ret = pb_file.save(&meta, raft_sync_meta(), &_log_counter_id, 0);
    //- In SGX-Raft, we have rollback prevention and thus sync is not needed
    // int ret = pb_file.save(&meta, false, &_log_counter_id, 0);

    timer.stop();
    PLOG_IF(ERROR, ret != 0) << "Fail to save meta to " << meta_path;
    LOG(INFO) << "log save_meta " << meta_path << " first_log_index = " 
              << first_log_index << " last_log_index = " << last_log_index
              << " time: " << timer.m_elapsed(0.0) << " ms";
    return ret;
}

int EncryptedSegmentTestLogStorage::load_meta() {
    sgxbutil::Timer timer;
    timer.start();

    std::string meta_path(_path);
    meta_path.append("/" BRAFT_SEGMENT_META_FILE);

    ProtoBufFile pb_file(meta_path);
    LogPBMeta meta;
    if (0 != pb_file.load(&meta, &_log_counter_id, 0)) {
        PLOG_IF(ERROR, errno != ENOENT) << "Fail to load meta from " << meta_path;
        return -1;
    }
    LOG(INFO) << "Func: " << __FUNCTION__ << " counter index = " << _log_counter_id;

    _first_log_index.store(meta.first_log_index());
    _last_log_index.store(meta.last_log_index());

    timer.stop();
    LOG(INFO) << "log load_meta " << meta_path << " first_log_index: " 
              << meta.first_log_index() << " last_log_index = " << meta.last_log_index()
              << " time: " << timer.u_elapsed();
    return 0;
}

sgxscoped_refptr<EncryptedSegmentTest> EncryptedSegmentTestLogStorage::open_segment() {
    // sgxscoped_refptr<EncryptedSegmentTest> prev_open_segment;
    {
        BAIDU_SCOPED_LOCK(_mutex);
        if (!_open_segment) {
            //- The open segment is initialized here.
            //- last_log_index() is usually 0 here
            _open_segment = new EncryptedSegmentTest(_path, first_log_index(), last_log_index());
            if (_open_segment->create() != 0) {
                _open_segment = NULL;
                return NULL;
            }
            //- TODO: This is an emtpy segment, so don't save meta
            // save_meta(first_log_index(), last_log_index());
        }
        // if (_open_segment->bytes() > FLAGS_raft_max_segment_size) {
        //     _segments[_open_segment->first_index()] = _open_segment;
        //     prev_open_segment.swap(_open_segment);
        // }
    }
    return _open_segment;
}

int EncryptedSegmentTestLogStorage::get_segment(int64_t index, sgxscoped_refptr<EncryptedSegmentTest>* ptr) {
    BAIDU_SCOPED_LOCK(_mutex);
    int64_t first_index = first_log_index();
    int64_t last_index = last_log_index();
    if (first_index == last_index + 1) {
        return -1;
    }
    if (index < first_index || index > last_index + 1) {
        LOG_IF(WARNING, index > last_index) << "Attempted to access entry " << index << " outside of log, "
            << " first_log_index: " << first_index
            << " last_log_index: " << last_index;
        return -1;
    } else if (index == last_index + 1) {
        return -1;
    }

    if (_open_segment && index >= _open_segment->first_index()) {
        *ptr = _open_segment;
        CHECK(ptr->get() != NULL);
    } else {
        CHECK(!_segments.empty());
        SegmentMap::iterator it = _segments.upper_bound(index);
        SegmentMap::iterator saved_it = it;
        --it;
        CHECK(it != saved_it);
        *ptr = it->second;
    }
    return 0;
}

void EncryptedSegmentTestLogStorage::list_files(std::vector<std::string>* seg_files) {
    BAIDU_SCOPED_LOCK(_mutex);
    seg_files->push_back(BRAFT_SEGMENT_META_FILE);
    for (SegmentMap::iterator it = _segments.begin(); it != _segments.end(); ++it) {
        sgxscoped_refptr<EncryptedSegmentTest>& segment = it->second;
        seg_files->push_back(segment->file_name());
    }
    if (_open_segment) {
        seg_files->push_back(_open_segment->file_name());
    }
}

void EncryptedSegmentTestLogStorage::sync() {
    std::vector<sgxscoped_refptr<EncryptedSegmentTest> > segments;
    {
        BAIDU_SCOPED_LOCK(_mutex);
        for (SegmentMap::iterator it = _segments.begin(); it != _segments.end(); ++it) {
            segments.push_back(it->second);
        }
    }

    for (size_t i = 0; i < segments.size(); i++) {
        segments[i]->sync(true);
    }
}

LogStorage* EncryptedSegmentTestLogStorage::new_instance(const std::string& uri) const {
    return new EncryptedSegmentTestLogStorage(uri);
}

sgxbutil::Status EncryptedSegmentTestLogStorage::gc_instance(const std::string& uri) const {
    sgxbutil::Status status;
    if (gc_dir(uri) != 0) {
        LOG(WARNING) << "Failed to gc log storage from path " << _path;
        status.set_error(EINVAL, "Failed to gc log storage from path %s", 
                         uri.c_str());
        return status;
    }
    LOG(INFO) << "Succeed to gc log storage from path " << uri;
    return status;
}

}