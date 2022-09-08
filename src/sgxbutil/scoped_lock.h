// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#ifndef SGX_BUTIL_BAIDU_SCOPED_LOCK_H
#define SGX_BUTIL_BAIDU_SCOPED_LOCK_H

// #include "butil/build_config.h"

#include <mutex>   // std::lock_guard

#include "sgxbutil/synchronization/lock.h"
#include "sgxbutil/macros.h"
#include "sgxbutil/logging.h"
#include "sgxbutil/errno.h"



// NOTE(gejun): c++11 deduces additional reference to the type.
namespace sgxbutil {
namespace detail {
template <typename T>
std::lock_guard<typename std::remove_reference<T>::type> get_lock_guard();
}  // namespace detail
}  // namespace sgxbutil

#define BAIDU_SCOPED_LOCK(ref_of_lock)                                  \
    decltype(::sgxbutil::detail::get_lock_guard<decltype(ref_of_lock)>()) \
    BAIDU_CONCAT(scoped_locker_dummy_at_line_, __LINE__)(ref_of_lock)

//- TODO: Comment out std:: namespace things when debugging outside the enclave to avoid collision
namespace std {

template<> class lock_guard<pthread_mutex_t> {
public:
    explicit lock_guard(pthread_mutex_t & mutex) : _pmutex(&mutex) {
#if !defined(NDEBUG)
        const int rc = pthread_mutex_lock(_pmutex);
        if (rc) {
            LOG(FATAL) << "Fail to lock pthread_mutex_t=" << _pmutex << ", " << berror(rc);
            _pmutex = NULL;
        }
#else
        pthread_mutex_lock(_pmutex);
#endif  // NDEBUG
    }
    
    ~lock_guard() {
#ifndef NDEBUG
        if (_pmutex) {
            pthread_mutex_unlock(_pmutex);
        }
#else
        pthread_mutex_unlock(_pmutex);
#endif
    }
    
private:
    DISALLOW_COPY_AND_ASSIGN(lock_guard);
    pthread_mutex_t* _pmutex;
};

template<> class lock_guard<pthread_spinlock_t> {
public:
    explicit lock_guard(pthread_spinlock_t & spin) : _pspin(&spin) {
#if !defined(NDEBUG)
        const int rc = pthread_spin_lock(_pspin);
        if (rc) {
            LOG(FATAL) << "Fail to lock pthread_spinlock_t=" << _pspin << ", " << berror(rc);
            _pspin = NULL;
        }
#else
        pthread_spin_lock(_pspin);
#endif  // NDEBUG
    }
    
    ~lock_guard() {
#ifndef NDEBUG
        if (_pspin) {
            pthread_spin_unlock(_pspin);
        }
#else
        pthread_spin_unlock(_pspin);
#endif
    }
    
private:
    DISALLOW_COPY_AND_ASSIGN(lock_guard);
    pthread_spinlock_t* _pspin;
};

template<> class unique_lock<pthread_mutex_t> {
    DISALLOW_COPY_AND_ASSIGN(unique_lock);
public:
    typedef pthread_mutex_t         mutex_type;
    unique_lock() : _mutex(NULL), _owns_lock(false) {}
    explicit unique_lock(mutex_type& mutex)
        : _mutex(&mutex), _owns_lock(true) {
        pthread_mutex_lock(_mutex);
    }
    unique_lock(mutex_type& mutex, defer_lock_t)
        : _mutex(&mutex), _owns_lock(false)
    {}
    unique_lock(mutex_type& mutex, try_to_lock_t) 
        : _mutex(&mutex), _owns_lock(pthread_mutex_trylock(&mutex) == 0)
    {}
    unique_lock(mutex_type& mutex, adopt_lock_t) 
        : _mutex(&mutex), _owns_lock(true)
    {}

    ~unique_lock() {
        if (_owns_lock) {
            pthread_mutex_unlock(_mutex);
        }
    }

    void lock() {
        if (_owns_lock) {
            CHECK(false) << "Detected deadlock issue";     
            return;
        }
#if !defined(NDEBUG)
        const int rc = pthread_mutex_lock(_mutex);
        if (rc) {
            LOG(FATAL) << "Fail to lock pthread_mutex=" << _mutex << ", " << berror(rc);
            return;
        }
        _owns_lock = true;
#else
        _owns_lock = true;
        pthread_mutex_lock(_mutex);
#endif  // NDEBUG
    }

    bool try_lock() {
        if (_owns_lock) {
            CHECK(false) << "Detected deadlock issue";     
            return false;
        }
        _owns_lock = !pthread_mutex_trylock(_mutex);
        return _owns_lock;
    }

    void unlock() {
        if (!_owns_lock) {
            CHECK(false) << "Invalid operation";
            return;
        }
        pthread_mutex_unlock(_mutex);
        _owns_lock = false;
    }

    void swap(unique_lock& rhs) {
        std::swap(_mutex, rhs._mutex);
        std::swap(_owns_lock, rhs._owns_lock);
    }

    mutex_type* release() {
        mutex_type* saved_mutex = _mutex;
        _mutex = NULL;
        _owns_lock = false;
        return saved_mutex;
    }

    mutex_type* mutex() { return _mutex; }
    bool owns_lock() const { return _owns_lock; }
    operator bool() const { return owns_lock(); }

private:
    mutex_type*                     _mutex;
    bool                            _owns_lock;
};

template<> class unique_lock<pthread_spinlock_t> {
    DISALLOW_COPY_AND_ASSIGN(unique_lock);
public:
    typedef pthread_spinlock_t  mutex_type;
    unique_lock() : _mutex(NULL), _owns_lock(false) {}
    explicit unique_lock(mutex_type& mutex)
        : _mutex(&mutex), _owns_lock(true) {
        pthread_spin_lock(_mutex);
    }

    ~unique_lock() {
        if (_owns_lock) {
            pthread_spin_unlock(_mutex);
        }
    }
    unique_lock(mutex_type& mutex, defer_lock_t)
        : _mutex(&mutex), _owns_lock(false)
    {}
    unique_lock(mutex_type& mutex, try_to_lock_t) 
        : _mutex(&mutex), _owns_lock(pthread_spin_trylock(&mutex) == 0)
    {}
    unique_lock(mutex_type& mutex, adopt_lock_t) 
        : _mutex(&mutex), _owns_lock(true)
    {}

    void lock() {
        if (_owns_lock) {
            CHECK(false) << "Detected deadlock issue";     
            return;
        }
#if !defined(NDEBUG)
        const int rc = pthread_spin_lock(_mutex);
        if (rc) {
            LOG(FATAL) << "Fail to lock pthread_spinlock=" << _mutex << ", " << berror(rc);
            return;
        }
        _owns_lock = true;
#else
        _owns_lock = true;
        pthread_spin_lock(_mutex);
#endif  // NDEBUG
    }

    bool try_lock() {
        if (_owns_lock) {
            CHECK(false) << "Detected deadlock issue";     
            return false;
        }
        _owns_lock = !pthread_spin_trylock(_mutex);
        return _owns_lock;
    }

    void unlock() {
        if (!_owns_lock) {
            CHECK(false) << "Invalid operation";
            return;
        }
        pthread_spin_unlock(_mutex);
        _owns_lock = false;
    }

    void swap(unique_lock& rhs) {
        std::swap(_mutex, rhs._mutex);
        std::swap(_owns_lock, rhs._owns_lock);
    }

    mutex_type* release() {
        mutex_type* saved_mutex = _mutex;
        _mutex = NULL;
        _owns_lock = false;
        return saved_mutex;
    }

    mutex_type* mutex() { return _mutex; }
    bool owns_lock() const { return _owns_lock; }
    operator bool() const { return owns_lock(); }

private:
    mutex_type*                     _mutex;
    bool                            _owns_lock;
};


}  // namespace std

namespace sgxbutil {

// Lock both lck1 and lck2 without the dead lock issue
template <typename Mutex1, typename Mutex2>
void double_lock(std::unique_lock<Mutex1> &lck1, std::unique_lock<Mutex2> &lck2) {
    // DCHECK(!lck1.owns_lock());
    // DCHECK(!lck2.owns_lock());
    volatile void* const ptr1 = lck1.mutex();
    volatile void* const ptr2 = lck2.mutex();
    // DCHECK_NE(ptr1, ptr2);
    if (ptr1 < ptr2) {
        lck1.lock();
        lck2.lock();
    } else {
        lck2.lock();
        lck1.lock();
    }
}
};

#endif  // SGX_BUTIL_BAIDU_SCOPED_LOCK_H
