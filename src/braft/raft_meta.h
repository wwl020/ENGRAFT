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
//          Xiong,Kai(xiongkai@baidu.com)

#ifndef BRAFT_RAFT_META_H
#define BRAFT_RAFT_META_H

#include "sgxbutil/memory/ref_counted.h"
#include "bthread/execution_queue.h"
#include "braft/storage.h"
#include "sgxbutil/state_cont/monotonic_counter.h"
#include "sgxbutil/state_cont/distri_state_mgr.h"

namespace braft {
//- delete KVBasedMergedMetaStorage
class FileBasedSingleMetaStorage;
class StateContinuousMetaStorage;

// Manage meta info of ONLY ONE raft instance
class FileBasedSingleMetaStorage : public RaftMetaStorage { 
public:
    explicit FileBasedSingleMetaStorage(const std::string& path)
        : _is_inited(false), _path(path), _term(1), _vote_counter_id(-1) {}
    FileBasedSingleMetaStorage() {}
    virtual ~FileBasedSingleMetaStorage() {}

    // init stable storage
    virtual sgxbutil::Status init();
    
    // set term and votedfor information
    virtual sgxbutil::Status set_term_and_votedfor(const int64_t term, const PeerId& peer_id, 
                                       const VersionedGroupId& group);
    
    // get term and votedfor information
    virtual sgxbutil::Status get_term_and_votedfor(int64_t* term, PeerId* peer_id, 
                                                const VersionedGroupId& group);

    RaftMetaStorage* new_instance(const std::string& uri) const;

    sgxbutil::Status gc_instance(const std::string& uri,
                              const VersionedGroupId& vgid) const;

private:
    static const char* _s_raft_meta;
    int load();
    int save();

    bool _is_inited;
    std::string _path;
    int64_t _term;
    PeerId _votedfor;
    sgxbutil::CounterID _vote_counter_id;
};

//- Store vote info in the cluster's online in-memory key-value storage,
// which has rollback prevention
class StateContinuousMetaStorage : public RaftMetaStorage {
public:
    explicit StateContinuousMetaStorage(const std::string& path)
        : _is_inited(false) {(void) path;}
    StateContinuousMetaStorage() {}
    virtual ~StateContinuousMetaStorage() {}

    // init state table
    virtual sgxbutil::Status init();
    
    // set term and votedfor information
    virtual sgxbutil::Status set_term_and_votedfor(const int64_t term, 
                                       const PeerId& peer_id, 
                                       const VersionedGroupId& group);
    
    // get term and votedfor information
    virtual sgxbutil::Status get_term_and_votedfor(int64_t* term, PeerId* peer_id, 
                                                const VersionedGroupId& group);

    RaftMetaStorage* new_instance(const std::string& uri) const;

    sgxbutil::Status gc_instance(const std::string& uri,
                              const VersionedGroupId& vgid) const;

private:
    bool _is_inited;
    sgxbutil::DistributedStateManager* _state_mgr;
};
}

#endif //~BRAFT_RAFT_META_H
