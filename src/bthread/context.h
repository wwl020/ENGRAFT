/*

    libcontext - a slightly more portable version of boost::context

    Copyright Martin Husemann 2013.
    Copyright Oliver Kowalke 2009.
    Copyright Sergue E. Leontiev 2013.
    Copyright Thomas Sailer 2013.
    Minor modifications by Tomasz Wlostowski 2016.

 Distributed under the Boost Software License, Version 1.0.
      (See accompanying file LICENSE_1_0.txt or copy at
            http://www.boost.org/LICENSE_1_0.txt)

*/

#ifndef BTHREAD_CONTEXT_H
#define BTHREAD_CONTEXT_H

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
//- Delete redundant code related to i386 or other arch/systems, because sgx-braft 
// only works for linux x86-64 platform

#define BTHREAD_CONTEXT_CALL_CONVENTION

typedef void* bthread_fcontext_t;

extern "C"{

intptr_t BTHREAD_CONTEXT_CALL_CONVENTION
bthread_jump_fcontext(bthread_fcontext_t * ofc, bthread_fcontext_t nfc,
                      intptr_t vp, bool preserve_fpu = false);
bthread_fcontext_t BTHREAD_CONTEXT_CALL_CONVENTION
bthread_make_fcontext(void* sp, size_t size, void (* fn)( intptr_t));

};

#endif  // BTHREAD_CONTEXT_H