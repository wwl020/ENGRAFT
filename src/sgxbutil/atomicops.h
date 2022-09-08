// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// For atomic operations on reference counts, see atomic_refcount.h.
// For atomic operations on sequence numbers, see atomic_sequence_num.h.

// The routines exported by this module are subtle.  If you use them, even if
// you get the code right, it will depend on careful reasoning about atomicity
// and memory ordering; it will be less readable, and harder to maintain.  If
// you plan to use these routines, you should have a good reason, such as solid
// evidence that performance would otherwise suffer, or there being no
// alternative.  You should assume only properties explicitly guaranteed by the
// specifications in this file.  You are almost certainly _not_ writing code
// just for the x86; if you assume x86 semantics, x86 hardware bugs and
// implementations on other archtectures will cause your code to break.  If you
// do not know what you are doing, avoid these routines, and use a Mutex.
//
// It is incorrect to make direct assignments to/from an atomic variable.
// You should use one of the Load or Store routines.  The NoBarrier
// versions are provided when no barriers are needed:
//   NoBarrier_Store()
//   NoBarrier_Load()
// Although there are currently no compiler enforcement, you are encouraged
// to use these.
//

#ifndef SGX_BUTIL_ATOMICOPS_H_
#define SGX_BUTIL_ATOMICOPS_H_

#include <stdint.h>

//- Useless
// #include "butil/build_config.h"

//-TODO: Change to "sgxbutil/macros.h" later.
#include "sgxbutil/macros.h"

namespace sgxbutil {
namespace subtle {

//- X86_64 Linux
typedef int32_t Atomic32;
typedef intptr_t Atomic64;


// Use AtomicWord for a machine-sized pointer.  It will use the Atomic32 or
// Atomic64 routines below, depending on your architecture.
typedef intptr_t AtomicWord;

// Atomically execute:
//      result = *ptr;
//      if (*ptr == old_value)
//        *ptr = new_value;
//      return result;
//
// I.e., replace "*ptr" with "new_value" if "*ptr" used to be "old_value".
// Always return the old value of "*ptr"
//
// This routine implies no memory barriers.
Atomic32 NoBarrier_CompareAndSwap(volatile Atomic32* ptr,
                                  Atomic32 old_value,
                                  Atomic32 new_value);

// Atomically store new_value into *ptr, returning the previous value held in
// *ptr.  This routine implies no memory barriers.
Atomic32 NoBarrier_AtomicExchange(volatile Atomic32* ptr, Atomic32 new_value);

// Atomically increment *ptr by "increment".  Returns the new value of
// *ptr with the increment applied.  This routine implies no memory barriers.
Atomic32 NoBarrier_AtomicIncrement(volatile Atomic32* ptr, Atomic32 increment);

Atomic32 Barrier_AtomicIncrement(volatile Atomic32* ptr,
                                 Atomic32 increment);

// These following lower-level operations are typically useful only to people
// implementing higher-level synchronization operations like spinlocks,
// mutexes, and condition-variables.  They combine CompareAndSwap(), a load, or
// a store with appropriate memory-ordering instructions.  "Acquire" operations
// ensure that no later memory access can be reordered ahead of the operation.
// "Release" operations ensure that no previous memory access can be reordered
// after the operation.  "Barrier" operations have both "Acquire" and "Release"
// semantics.   A MemoryBarrier() has "Barrier" semantics, but does no memory
// access.
Atomic32 Acquire_CompareAndSwap(volatile Atomic32* ptr,
                                Atomic32 old_value,
                                Atomic32 new_value);
Atomic32 Release_CompareAndSwap(volatile Atomic32* ptr,
                                Atomic32 old_value,
                                Atomic32 new_value);

void MemoryBarrier();
void NoBarrier_Store(volatile Atomic32* ptr, Atomic32 value);
void Acquire_Store(volatile Atomic32* ptr, Atomic32 value);
void Release_Store(volatile Atomic32* ptr, Atomic32 value);

Atomic32 NoBarrier_Load(volatile const Atomic32* ptr);
Atomic32 Acquire_Load(volatile const Atomic32* ptr);
Atomic32 Release_Load(volatile const Atomic32* ptr);

// 64-bit atomic operations (only available on 64-bit processors).
Atomic64 NoBarrier_CompareAndSwap(volatile Atomic64* ptr,
                                  Atomic64 old_value,
                                  Atomic64 new_value);
Atomic64 NoBarrier_AtomicExchange(volatile Atomic64* ptr, Atomic64 new_value);
Atomic64 NoBarrier_AtomicIncrement(volatile Atomic64* ptr, Atomic64 increment);
Atomic64 Barrier_AtomicIncrement(volatile Atomic64* ptr, Atomic64 increment);

Atomic64 Acquire_CompareAndSwap(volatile Atomic64* ptr,
                                Atomic64 old_value,
                                Atomic64 new_value);
Atomic64 Release_CompareAndSwap(volatile Atomic64* ptr,
                                Atomic64 old_value,
                                Atomic64 new_value);
void NoBarrier_Store(volatile Atomic64* ptr, Atomic64 value);
void Acquire_Store(volatile Atomic64* ptr, Atomic64 value);
void Release_Store(volatile Atomic64* ptr, Atomic64 value);
Atomic64 NoBarrier_Load(volatile const Atomic64* ptr);
Atomic64 Acquire_Load(volatile const Atomic64* ptr);
Atomic64 Release_Load(volatile const Atomic64* ptr);
}  // namespace subtle
}  // namespace sgxbutil
// Include our platform specific implementation.
//- COMPILER_GCC, ARCH_CPU_X86_FAMILY
#include "sgxbutil/atomicops_internals_x86_gcc.h"


// ========= Provide butil::atomic<T> =========
//- Nota that __cplusplus >= 201103L must hold.

// gcc supports atomic thread fence since 4.8 checkout
// #if defined(__clang__) || \
//     !defined(__GNUC__) || \
//     (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 >= 40800)
//- To support atomic thread fence,
//- GCC version must be higher than 4.8, or use clang.
#include <atomic>

namespace sgxbutil {
using ::std::memory_order;
using ::std::memory_order_relaxed;
using ::std::memory_order_consume;
using ::std::memory_order_acquire;
using ::std::memory_order_release;
using ::std::memory_order_acq_rel;
using ::std::memory_order_seq_cst;
using ::std::atomic_thread_fence;
using ::std::atomic_signal_fence;
template <typename T> class atomic : public ::std::atomic<T> {
public:
    atomic() {}
    atomic(T v) : ::std::atomic<T>(v) {}
    atomic& operator=(T v) {
        this->store(v);
        return *this;
    }
private:
    DISALLOW_COPY_AND_ASSIGN(atomic);
    // Make sure memory layout of std::atomic<T> and boost::atomic<T>
    // are same so that different compilation units seeing different 
    // definitions(enable C++11 or not) should be compatible.
    BAIDU_CASSERT(sizeof(T) == sizeof(::std::atomic<T>), size_must_match);
};
} // namespace sgxbutil


// static_atomic<> is a work-around for C++03 to declare global atomics
// w/o constructing-order issues. It can also used in C++11 though.
// Example:
//   butil::static_atomic<int> g_counter = BUTIL_STATIC_ATOMIC_INIT(0);
// Notice that to make static_atomic work for C++03, it cannot be
// initialized by a constructor. Following code is wrong:
//   butil::static_atomic<int> g_counter(0); // Not compile

#define BUTIL_STATIC_ATOMIC_INIT(val) { (val) }

namespace sgxbutil {
template <typename T> struct static_atomic {
    T val;

    // NOTE: the memory_order parameters must be present.
    T load(memory_order o) { return ref().load(o); }
    void store(T v, memory_order o) { return ref().store(v, o); }
    T exchange(T v, memory_order o) { return ref().exchange(v, o); }
    bool compare_exchange_weak(T& e, T d, memory_order o)
    { return ref().compare_exchange_weak(e, d, o); }
    bool compare_exchange_weak(T& e, T d, memory_order so, memory_order fo)
    { return ref().compare_exchange_weak(e, d, so, fo); }
    bool compare_exchange_strong(T& e, T d, memory_order o)
    { return ref().compare_exchange_strong(e, d, o); }
    bool compare_exchange_strong(T& e, T d, memory_order so, memory_order fo)
    { return ref().compare_exchange_strong(e, d, so, fo); }
    T fetch_add(T v, memory_order o) { return ref().fetch_add(v, o); }
    T fetch_sub(T v, memory_order o) { return ref().fetch_sub(v, o); }
    T fetch_and(T v, memory_order o) { return ref().fetch_and(v, o); }
    T fetch_or(T v, memory_order o) { return ref().fetch_or(v, o); }
    T fetch_xor(T v, memory_order o) { return ref().fetch_xor(v, o); }
    static_atomic& operator=(T v) {
        store(v, memory_order_seq_cst);
        return *this;
    }
private:
    DISALLOW_ASSIGN(static_atomic);
    BAIDU_CASSERT(sizeof(T) == sizeof(atomic<T>), size_must_match);
    atomic<T>& ref() {
        // Suppress strict-alias warnings.
        atomic<T>* p = reinterpret_cast<atomic<T>*>(&val);
        return *p;
    }
};
} // namespace sgxbutil

#endif  // SGX_BUTIL_ATOMICOPS_H_
