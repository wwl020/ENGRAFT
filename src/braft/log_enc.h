#ifndef BRAFT_LOG_ENCRYPTED_H
#define BRAFT_LOG_ENCRYPTED_H

#include <vector>
#include <map>
#include "sgxbutil/memory/ref_counted.h"
#include "sgxbutil/atomicops.h"
#include "sgxbutil/iobuf.h"
#include "sgxbutil/logging.h"
#include "braft/log_entry.h"
#include "braft/storage.h"
#include "braft/util.h"
#include "sgxbutil/state_cont/monotonic_counter.h"

namespace braft {

class BAIDU_CACHELINE_ALIGNMENT EncryptedSegment 
        : public sgxbutil::RefCountedThreadSafe<EncryptedSegment> {
public:
    EncryptedSegment(const std::string& path, const int64_t first_index, const int64_t last_index)
        : _path(path), _bytes(0),
        _fd(-1), _is_open(true),
        _first_index(first_index), _last_index(last_index)
    {}

    struct EntryHeader;

    // create open segment
    int create();

    // load open or closed segment
    // open fd, load index, truncate uncompleted entry
    int load(ConfigurationManager* configuration_manager);

    // serialize entry, and append to open segment
    int append(const LogEntry* entry);

    // get entry by index
    LogEntry* get(const int64_t index) const;

    // get entry's term by index
    int64_t get_term(const int64_t index) const;

    // close open segment
    // int close(bool will_sync = true);

    // sync open segment
    int sync(bool will_sync);

    // unlink segment
    int unlink();

    // truncate segment to last_index_kept
    //- (last_index_kept, infinity) will be discarded
    int truncate_suffix(const int64_t last_index_kept);

    //- delete logs from the beginning of this segment
    //- [1, first_index_kept) will be discarded
    int truncate_prefix(const int64_t first_index_kept);

    bool is_open() const {
        return _is_open;
    }

    int64_t bytes() const {
        return _bytes;
    }

    int64_t first_index() const {
        return _first_index;
    }

    int64_t last_index() const {
        return _last_index.load(sgxbutil::memory_order_consume);
    }

    std::string file_name();
private:
friend class sgxbutil::RefCountedThreadSafe<EncryptedSegment>;
    ~EncryptedSegment() {
        if (_fd >= 0) {
            ::close(_fd);
            _fd = -1;
        }
    }

    struct LogMeta {
        off_t offset;
        size_t length;
        int64_t term;
    };

    //- Load log entry header only
    int _load_entry(off_t offset, EntryHeader *head, sgxbutil::IOBuf *body, 
                    size_t size_hint) const;
    //- Load a log entry completely                    
    int _load_whole_entry(off_t offset, EntryHeader *head, sgxbutil::IOBuf *body, 
                    size_t size_hint) const;
                    
    //- Given iobuf, extract header info 
    //- (iv, log_index/term/type, mac, log_length)
    //- return value is log_length            
    int _extract_log_entry_header(sgxbutil::IOBuf read_iobuf, unsigned char* iv, unsigned char* aad, unsigned char* mac, EntryHeader* head) const;

    int _get_meta(int64_t index, LogMeta* meta) const;

    std::string _path;
    int64_t _bytes;
    mutable raft_mutex_t _mutex;
    int _fd;
    bool _is_open;
    //- _first_index should be modified when truncating from the beginning
    //- so "const" is removed
    int64_t _first_index;
    sgxbutil::atomic<int64_t> _last_index;
    std::vector<std::pair<int64_t/*offset*/, int64_t/*term*/> > _offset_and_term;
};


class EncryptedSegmentLogStorage : public LogStorage {
public:
    typedef std::map<int64_t, sgxscoped_refptr<EncryptedSegment> > SegmentMap;

    explicit EncryptedSegmentLogStorage(const std::string& path, bool enable_sync = true)
        : _path(path)
        //- "-1" Indicates no valid counter
        , _log_counter_id(-1) 
        , _first_log_index(1)
        , _last_log_index(0)
        , _enable_sync(enable_sync)
    {} 

    EncryptedSegmentLogStorage()    
        //- "-1" Indicates no valid counter
        : _log_counter_id(-1) 
        , _first_log_index(1)
        , _last_log_index(0)
        , _enable_sync(true)
    {}

    virtual ~EncryptedSegmentLogStorage() {}

    // init logstorage, check consistency and integrity
    virtual int init(ConfigurationManager* configuration_manager);

    // first log index in log
    virtual int64_t first_log_index() {
        return _first_log_index.load(sgxbutil::memory_order_acquire);
    }

    // last log index in log
    virtual int64_t last_log_index();

    // get logentry by index
    virtual LogEntry* get_entry(const int64_t index);

    // get logentry's term by index
    virtual int64_t get_term(const int64_t index);

    // append entry to log
    int append_entry(const LogEntry* entry);

    // append entries to log and update IOMetric, return success append number
    virtual int append_entries(const std::vector<LogEntry*>& entries, IOMetric* metric);

    // delete logs from storage's head, [1, first_index_kept) will be discarded
    virtual int truncate_prefix(const int64_t first_index_kept);

    // delete uncommitted logs from storage's tail, (last_index_kept, infinity) will be discarded
    virtual int truncate_suffix(const int64_t last_index_kept);

    virtual int reset(const int64_t next_log_index);

    LogStorage* new_instance(const std::string& uri) const;
    
    sgxbutil::Status gc_instance(const std::string& uri) const;

    SegmentMap& segments() {
        return _segments;
    }

    void list_files(std::vector<std::string>* seg_files);

    void sync();
private:
    sgxscoped_refptr<EncryptedSegment> open_segment();
    int save_meta(const int64_t first_log_index, const int64_t last_log_index);
    int load_meta();
    int list_segments(bool is_empty);
    int load_segments(ConfigurationManager* configuration_manager);
    int get_segment(int64_t log_index, sgxscoped_refptr<EncryptedSegment>* ptr);
    void pop_segments(
            int64_t first_index_kept, 
            std::vector<sgxscoped_refptr<EncryptedSegment> >* poped);


    std::string _path;
    //- Deal with state-continuity
    sgxbutil::CounterID _log_counter_id;
    sgxbutil::atomic<int64_t> _first_log_index;
    sgxbutil::atomic<int64_t> _last_log_index;
    raft_mutex_t _mutex;
    SegmentMap _segments;
    sgxscoped_refptr<EncryptedSegment> _open_segment;
    bool _enable_sync;
};

}  //  namespace braft

#endif // BRAFT_LOG_ENCRYPTED_H
