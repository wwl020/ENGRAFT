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

#include <errno.h>
#include "sgxbutil/time.h"
#include "sgxbutil/logging.h"
#include "sgxbutil/file_util.h"                         // sgxbutil::CreateDirectory
#include "brpc/reloadable_flags.h"
#include "braft/util.h"
#include "braft/protobuf_file.h"
#include "braft/local_storage.pb.h"
#include "braft/raft_meta.h"

namespace braft {

//- Remove bvar

// static bvar::LatencyRecorder g_load_pb_raft_meta("raft_load_pb_raft_meta");
// static bvar::LatencyRecorder g_save_pb_raft_meta("raft_save_pb_raft_meta");


const char* FileBasedSingleMetaStorage::_s_raft_meta = "raft_meta";

#define global_mss_manager MetaStorageManager::GetInstance()

 
// FileBasedSingleMetaStorage
sgxbutil::Status FileBasedSingleMetaStorage::init() {
    sgxbutil::Status status;
    if (_is_inited) {
        return status;
    }

    sgxbutil::FilePath dir_path(_path);
    sgxbutil::File::Error e;
    if (!sgxbutil::CreateDirectoryAndGetError(
                dir_path, &e, FLAGS_raft_create_parent_directories)) {
        LOG(ERROR) << "Fail to create " << dir_path.value() << " : " << e;
        status.set_error(e, "Fail to create dir when init SingleMetaStorage, "
                         "path: %s", _path.c_str());
        return status;
    }

    int ret = load();
    if (ret != 0) {
        LOG(ERROR) << "Fail to load pb meta when init single stable storage"
                      ", path: " << _path;
        status.set_error(EIO, "Fail to load pb meta when init stabel storage"
                         ", path: %s", _path.c_str());
        return status;
    }

    _is_inited = true;
    return status;
}

sgxbutil::Status FileBasedSingleMetaStorage::set_term_and_votedfor(const int64_t term, 
            const PeerId& peer_id, const VersionedGroupId&) {
    sgxbutil::Status status;
    if (!_is_inited) {
        status.set_error(EINVAL, "SingleMetaStorage not init, path: %s", 
                         _path.c_str());
        return status;
    }   
    _term = term;
    _votedfor = peer_id;
    if (save() != 0) {
        status.set_error(EIO, "SingleMetaStorage failed to save pb meta, path: %s", 
                         _path.c_str());
        return status;
    }
    return status;
}
 
sgxbutil::Status FileBasedSingleMetaStorage::get_term_and_votedfor(int64_t* term, 
                                PeerId* peer_id, const VersionedGroupId& group) {
    sgxbutil::Status status;
    if (!_is_inited) {
        status.set_error(EINVAL, "SingleMetaStorage not init, path: %s", 
                         _path.c_str());
        return status;
    }   
    *term = _term;
    *peer_id = _votedfor;
    return status;
}

//- Load meta info from a single file
int FileBasedSingleMetaStorage::load() {
    sgxbutil::Timer timer;
    timer.start();
 
    std::string path(_path);
    path.append("/");
    path.append(_s_raft_meta);

    ProtoBufFile pb_file(path);

    StablePBMeta meta;
    int ret = pb_file.load(&meta, &_vote_counter_id, 1);
    if (ret == 0) {
        _term = meta.term();
        ret = _votedfor.parse(meta.votedfor());
    } else if (errno == ENOENT) {
        ret = 0;
    } else {
        PLOG(ERROR) << "Fail to load meta from " << path;
    }
    
    timer.stop();
    // Only reload process will load stable meta of raft instances,
    // reading just go through memory
    // g_load_pb_raft_meta << timer.u_elapsed(); //- Remove bvar
    LOG(INFO) << "Loaded single stable meta, path " << _path
              << " term " << _term 
              << " votedfor " << _votedfor.to_string() 
              << " time: " << timer.u_elapsed();
    return ret;
}

//- Store term and vote in meta
int FileBasedSingleMetaStorage::save() {
    sgxbutil::Timer timer;
    timer.start();

    StablePBMeta meta;
    meta.set_term(_term);
    meta.set_votedfor(_votedfor.to_string());

    std::string path(_path);
    path.append("/");
    path.append(_s_raft_meta);

    ProtoBufFile pb_file(path);
    int ret = pb_file.save(&meta, raft_sync_meta(), &_vote_counter_id, 1);
    PLOG_IF(ERROR, ret != 0) << "Fail to save meta to " << path;

    timer.stop();
    // g_save_pb_raft_meta << timer.u_elapsed(); //- Remove bvar
    LOG(INFO) << "Saved single stable meta, path " << _path
              << " term " << _term 
              << " votedfor " << _votedfor.to_string() 
              << " time: " << timer.u_elapsed();
    return ret;
}

RaftMetaStorage* FileBasedSingleMetaStorage::new_instance(
                                        const std::string& uri) const {
    return new FileBasedSingleMetaStorage(uri);
}

sgxbutil::Status FileBasedSingleMetaStorage::gc_instance(const std::string& uri, 
                                        const VersionedGroupId& vgid) const {
    sgxbutil::Status status;
    if (0 != gc_dir(uri)) {
        LOG(WARNING) << "Group " << vgid << " failed to gc single stable storage"
                        ", path: " << uri;
        status.set_error(EIO, "Group %s failed to gc single stable storage"
                         ", path: %s", vgid.c_str(), uri.c_str());
        return status;
    }
    LOG(INFO) << "Group " << vgid << " succeed to gc single stable storage"
                 ", path: " << uri;
    return status;
}

//- StateContinuousMetaStorage
sgxbutil::Status StateContinuousMetaStorage::init() {
    sgxbutil::Status status;
    if (_is_inited) {
        return status;
    }
    _state_mgr = sgxbutil::GetGlobalDistributedStateManager();
    _is_inited = true;
    return status;
}

sgxbutil::Status StateContinuousMetaStorage::set_term_and_votedfor(const int64_t term, 
            const PeerId& peer_id, const VersionedGroupId& group) {
    VLOG(79) << "Func: " << __FUNCTION__ << " The term-val = " << term;
    sgxbutil::Status status;
    (void) group;
    if (!_is_inited) {
        status.set_error(EINVAL, "StateContinuousMetaStorage is not initialized");
        return status;
    }

    if (_state_mgr->set_term_and_votedfor(term, peer_id) != 0) {
        status.set_error(EFAULT, "StateContinuousMetaStorage set vote info failed");
        return status;
    }
    return status;
}
 
sgxbutil::Status StateContinuousMetaStorage::get_term_and_votedfor(int64_t* term, 
                                PeerId* peer_id, const VersionedGroupId& group) {
    sgxbutil::Status status;
    (void) group;
    if (!_is_inited) {
        status.set_error(EINVAL, "StateContinuousMetaStorage not init");
        return status;
    }
    if (_state_mgr->get_term_and_votedfor(term, peer_id) != 0) {
        LOG(ERROR) << "Distributed state manager can't get term and voted_for";
        status.set_error(EFAULT, "Distributed state manager can't get term and voted_for");
        return status;
    }
    return status;
}

RaftMetaStorage* StateContinuousMetaStorage::new_instance(
                                        const std::string& uri) const {
    return new StateContinuousMetaStorage(uri);
}

sgxbutil::Status StateContinuousMetaStorage::gc_instance(const std::string& uri, 
                                        const VersionedGroupId& vgid) const {
    sgxbutil::Status status;
    (void) uri;
    (void) vgid;
    return status;
}
}
