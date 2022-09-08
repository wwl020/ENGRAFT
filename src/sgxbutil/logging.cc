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

// Date: 2012-10-08 23:53:50

#include "sgxbutil/logging.h"

#if !BRPC_WITH_GLOG

#include <sys/time.h> // timespec doesn't seem to be in <time.h>
#include <time.h>

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_PATH PATH_MAX
typedef FILE* FileHandle;
typedef pthread_mutex_t* MutexHandle;

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <ostream>
#include <string>

#include "sgxbutil/file_util.h" //- ported
// #include "butil/debug/alias.h"
// #include "butil/debug/debugger.h"
// #include "butil/debug/stack_trace.h"
#include "sgxbutil/posix/eintr_wrapper.h" //- ported
#include "sgxbutil/strings/string_util.h" //- ported
#include "sgxbutil/strings/stringprintf.h" //- ported
// #include "sgxbutil/strings/utf_string_conversions.h"
#include "sgxbutil/synchronization/lock.h" //- ported
// #include "butil/threading/platform_thread.h"
#include "sgxbutil/errno.h"
#include "sgxbutil/fd_guard.h" //- ported
#include <fcntl.h>

#include <map>
#include <vector>
#include <deque>
#include <limits>
#include "google/gflags/gflags.h"
#include "sgxbutil/atomicops.h" //- ported
#include "sgxbutil/thread_local.h" //- ported
#include "sgxbutil/scoped_lock.h" //- ported
#include "sgxbutil/string_splitter.h" //- ported
#include "sgxbutil/time.h" //- ported
#include "sgxbutil/containers/doubly_buffered_data.h" //- ported
#include "sgxbutil/memory/singleton.h"
#include "sgxbutil/endpoint.h" //- ported
#include "bthread/bthread.h"

#if RUN_OUTSIDE_SGX
#include "host/host_utils.h"
#else 
#include "interface_t.h"
#endif

namespace logging {

DEFINE_bool(crash_on_fatal_log, false,
            "Crash process when a FATAL log is printed");
DEFINE_bool(print_stack_on_check, true,
            "Print the stack trace when a CHECK was failed");
//- Default: 0, Braft: 89, Timer-things: 85
//- If want to conduct running time evaluation, set it to 85
//- If want to see all verbose logs, set it to 89
DEFINE_int32(v, 79, "Show all VLOG(m) messages for m <= this."
             " Overridable by --vmodule.");
DEFINE_string(vmodule, "", "per-module verbose level."
              " Argument is a comma-separated list of MODULE_NAME=LOG_LEVEL."
              " MODULE_NAME is a glob pattern, matched against the filename base"
              " (that is, name ignoring .cpp/.h)."
              " LOG_LEVEL overrides any value given by --v.");

DEFINE_bool(log_process_id, false, "Log process id");

DEFINE_int32(minloglevel, 3, "Any log at or above this level will be "
             "displayed. Anything below this level will be silently ignored. "
             "0=INFO 1=NOTICE 2=WARNING 3=ERROR 4=FATAL");

DEFINE_bool(log_hostname, false, "Add host after pid in each log so"
            " that we know where logs came from when using aggregation tools"
            " like ELK.");

DEFINE_bool(log_year, false, "Log year in datetime part in each log");

namespace {

LoggingDestination logging_destination = LOG_DEFAULT;

// For BLOG_ERROR and above, always print to stderr.
const int kAlwaysPrintErrorLevel = BLOG_ERROR;

// Which log file to use? This is initialized by InitLogging or
// will be lazily initialized to the default value when it is
// first needed.
typedef std::string PathString;
PathString* log_file_name = NULL;

// this file is lazily opened and the handle may be NULL
FileHandle log_file = NULL;

// Should we pop up fatal debug messages in a dialog?
bool show_error_dialogs = false;

// An assert handler override specified by the client to be called instead of
// the debug message dialog and process termination.
LogAssertHandler log_assert_handler = NULL;

// Helper functions to wrap platform differences.

int32_t CurrentProcessId() {
    return getpid();
}

void DeleteFilePath(const PathString& log_name) {
    unlink(log_name.c_str());
}

static PathString GetProcessName() {
    sgxbutil::fd_guard fd(open("/proc/self/cmdline", O_RDONLY));
    if (fd < 0) {
        return "unknown";
    }
    char buf[512];
    const ssize_t len = read(fd, buf, sizeof(buf) - 1);
    if (len <= 0) {
        return "unknown";
    }
    buf[len] = '\0';
    // Not string(buf, len) because we needs to buf to be truncated at first \0.
    // Under gdb, the first part of cmdline may include path.
    return sgxbutil::FilePath(std::string(buf)).BaseName().value();
}

PathString GetDefaultLogFile() {
    return GetProcessName() + ".log";
}

// This class acts as a wrapper for locking the logging files.
// LoggingLock::Init() should be called from the main thread before any logging
// is done. Then whenever logging, be sure to have a local LoggingLock
// instance on the stack. This will ensure that the lock is unlocked upon
// exiting the frame.
// LoggingLocks can not be nested.
class LoggingLock {
public:
    LoggingLock() {
        LockLogging();
    }

    ~LoggingLock() {
        UnlockLogging();
    }

    static void Init(LogLockingState lock_log, const PathChar* new_log_file) {
        if (initialized)
            return;
        lock_log_file = lock_log;
        if (lock_log_file == LOCK_LOG_FILE) {
        } else {
            log_lock = new sgxbutil::Mutex;
        }
        initialized = true;
    }

private:
    static void LockLogging() {
        if (lock_log_file == LOCK_LOG_FILE) {
            pthread_mutex_lock(&log_mutex);
        } else {
            // use the lock
            log_lock->lock();
        }
    }

    static void UnlockLogging() {
        if (lock_log_file == LOCK_LOG_FILE) {
            pthread_mutex_unlock(&log_mutex);
        } else {
            log_lock->unlock();
        }
    }

    // The lock is used if log file locking is false. It helps us avoid problems
    // with multiple threads writing to the log file at the same time.
    static sgxbutil::Mutex* log_lock;

    // When we don't use a lock, we are using a global mutex. We need to do this
    // because LockFileEx is not thread safe.
    static pthread_mutex_t log_mutex;

    static bool initialized;
    static LogLockingState lock_log_file;
};

// static
bool LoggingLock::initialized = false;
// static
sgxbutil::Mutex* LoggingLock::log_lock = NULL;
// static
LogLockingState LoggingLock::lock_log_file = LOCK_LOG_FILE;

pthread_mutex_t LoggingLock::log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Called by logging functions to ensure that debug_file is initialized
// and can be used for writing. Returns false if the file could not be
// initialized. debug_file will be NULL in this case.
bool InitializeLogFileHandle() {
    if (log_file)
        return true;

    if (!log_file_name) {
        // Nobody has called InitLogging to specify a debug log file, so here we
        // initialize the log file name to a default.
        log_file_name = new PathString(GetDefaultLogFile());
    }

    if ((logging_destination & LOG_TO_FILE) != 0) {
        log_file = fopen(log_file_name->c_str(), "a");
        if (log_file == NULL) {
            fprintf(stderr, "Fail to fopen %s", log_file_name->c_str());
            return false;
        }
    }

    return true;
}

void CloseFile(FileHandle log) {
    fclose(log);
}

void CloseLogFileUnlocked() {
    if (!log_file)
        return;

    CloseFile(log_file);
    log_file = NULL;
}

}  // namespace

LoggingSettings::LoggingSettings()
    : logging_dest(LOG_DEFAULT),
      log_file(NULL),
      lock_log(LOCK_LOG_FILE),
      delete_old(APPEND_TO_OLD_LOG_FILE) {}

bool BaseInitLoggingImpl(const LoggingSettings& settings) {

    logging_destination = settings.logging_dest;

    // ignore file options unless logging to file is set.
    if ((logging_destination & LOG_TO_FILE) == 0)
        return true;

    LoggingLock::Init(settings.lock_log, settings.log_file);
    LoggingLock logging_lock;

    // Calling InitLogging twice or after some log call has already opened the
    // default log file will re-initialize to the new options.
    CloseLogFileUnlocked();

    if (!log_file_name)
        log_file_name = new PathString();
    if (settings.log_file) {
        *log_file_name = settings.log_file;
    } else {
        *log_file_name = GetDefaultLogFile();
    }
    if (settings.delete_old == DELETE_OLD_LOG_FILE)
        DeleteFilePath(*log_file_name);

    return InitializeLogFileHandle();
}

void SetMinLogLevel(int level) {
    FLAGS_minloglevel = std::min(BLOG_FATAL, level);
}

int GetMinLogLevel() {
    return FLAGS_minloglevel;
}

void SetShowErrorDialogs(bool enable_dialogs) {
    show_error_dialogs = enable_dialogs;
}

void SetLogAssertHandler(LogAssertHandler handler) {
    log_assert_handler = handler;
}

const char* const log_severity_names[LOG_NUM_SEVERITIES] = {
    "INFO", "NOTICE", "WARNING", "ERROR", "FATAL" };

inline void log_severity_name(std::ostream& os, int severity) {
    if (severity < 0) {
        // Add extra space to separate from following datetime.
        os << 'V' << -severity << ' ';
    } else if (severity < LOG_NUM_SEVERITIES) {
        os << log_severity_names[severity][0];
    } else {
        os << 'U';
    }
}

void print_log_prefix(std::ostream& os,
                      int severity, const char* file, int line) {
    log_severity_name(os, severity);

    uint64_t current_nano_sec = 0;
    struct tm local_tm = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL};
    ocall_get_logging_time(&local_tm, &current_nano_sec);

    const char prev_fill = os.fill('0');
    if (FLAGS_log_year) {
        os << std::setw(4) << local_tm.tm_year + 1900;
    }
    os << std::setw(2) << local_tm.tm_mon + 1
       << std::setw(2) << local_tm.tm_mday << ' '
       << std::setw(2) << local_tm.tm_hour << ':'
       << std::setw(2) << local_tm.tm_min << ':'
       << std::setw(2) << local_tm.tm_sec;
    os << '.' << std::setw(9) << current_nano_sec;

    if (FLAGS_log_process_id) {
        os << ' ' << std::setfill(' ') << std::setw(5) << CurrentProcessId();
    }    
    // os << ' ' << std::setfill(' ') << std::setw(5) << bthread_self() << std::setfill('0');
    os << ' ' << std::setfill(' ') << std::setw(5) << pthread_self() << std::setfill('0');
       
    if (FLAGS_log_hostname) {
        sgxbutil::StringPiece hostname(sgxbutil::my_hostname());
        if (hostname.ends_with(".baidu.com")) { // make it shorter
            hostname.remove_suffix(10);
        }
        os << ' ' << hostname;
    }
    os << ' ' << file << ':' << line << "] ";
    os.fill(prev_fill);
}

// A log message handler that gets notified of every log message we process.
class DoublyBufferedLogSink : public sgxbutil::DoublyBufferedData<LogSink*> {
public:
    DoublyBufferedLogSink() {}
    static DoublyBufferedLogSink* GetInstance();
private:
friend struct DefaultSingletonTraits<DoublyBufferedLogSink>;
    DISALLOW_COPY_AND_ASSIGN(DoublyBufferedLogSink);
};

DoublyBufferedLogSink* DoublyBufferedLogSink::GetInstance() {
    return Singleton<DoublyBufferedLogSink,
                     LeakySingletonTraits<DoublyBufferedLogSink> >::get();
}

struct SetLogSinkFn {
    LogSink* new_sink;
    LogSink* old_sink;

    bool operator()(LogSink*& ptr) {
        old_sink = ptr;
        ptr = new_sink;
        return true;
    }
};

LogSink* SetLogSink(LogSink* sink) {
    SetLogSinkFn fn = { sink, NULL };
    CHECK(DoublyBufferedLogSink::GetInstance()->Modify(fn));
    return fn.old_sink;
}

// Explicit instantiations for commonly used comparisons.
template std::string* MakeCheckOpString<int, int>(
    const int&, const int&, const char* names);
template std::string* MakeCheckOpString<unsigned long, unsigned long>(
    const unsigned long&, const unsigned long&, const char* names);
template std::string* MakeCheckOpString<unsigned long, unsigned int>(
    const unsigned long&, const unsigned int&, const char* names);
template std::string* MakeCheckOpString<unsigned int, unsigned long>(
    const unsigned int&, const unsigned long&, const char* names);
template std::string* MakeCheckOpString<std::string, std::string>(
    const std::string&, const std::string&, const char* name);


bool StringSink::OnLogMessage(int severity, const char* file, int line, 
                              const sgxbutil::StringPiece& content) {
    std::ostringstream prefix_os;
    print_log_prefix(prefix_os, severity, file, line);
    const std::string prefix = prefix_os.str();
    {
        sgxbutil::AutoLock lock_guard(_lock);
        reserve(size() + prefix.size() + content.size());
        append(prefix);
        append(content.data(), content.size());
    }
    return true;
}

CharArrayStreamBuf::~CharArrayStreamBuf() {
    free(_data);
}

int CharArrayStreamBuf::overflow(int ch) {
    if (ch == std::streambuf::traits_type::eof()) {
        return ch;
    }
    size_t new_size = std::max(_size * 3 / 2, (size_t)64);
    char* new_data = (char*)malloc(new_size);
    if (BAIDU_UNLIKELY(new_data == NULL)) {
        setp(NULL, NULL);
        return std::streambuf::traits_type::eof();
    }
    memcpy(new_data, _data, _size);
    free(_data);
    _data = new_data;
    const size_t old_size = _size;
    _size = new_size;
    setp(_data, _data + new_size);
    pbump(old_size);
    // if size == 1, this function will call overflow again.
    return sputc(ch);
}

int CharArrayStreamBuf::sync() {
    // data are already there.
    return 0;
}

void CharArrayStreamBuf::reset() {
    setp(_data, _data + _size);
}

LogStream& LogStream::SetPosition(const PathChar* file, int line,
                                  LogSeverity severity) {
    _file = file;
    _line = line;
    _severity = severity;
    return *this;
}

static pthread_key_t stream_pkey;
static pthread_once_t create_stream_key_once = PTHREAD_ONCE_INIT;
static void destroy_tls_streams(void* data) {
    if (data == NULL) {
        return;
    }
    LogStream** a = (LogStream**)data;
    for (int i = 0; i <= LOG_NUM_SEVERITIES; ++i) {
        delete a[i];
    }
    delete[] a;
}
static void create_stream_key_or_die() {
    int rc = pthread_key_create(&stream_pkey, destroy_tls_streams);
    if (rc) {
        fprintf(stderr, "Fail to pthread_key_create");
        exit(1);
    }
}
static LogStream** get_tls_stream_array() {
    pthread_once(&create_stream_key_once, create_stream_key_or_die);
    return (LogStream**)pthread_getspecific(stream_pkey);
}

static LogStream** get_or_new_tls_stream_array() {
    LogStream** a = get_tls_stream_array();
    if (a == NULL) {
        a = new LogStream*[LOG_NUM_SEVERITIES + 1];
        memset(a, 0, sizeof(LogStream*) * (LOG_NUM_SEVERITIES + 1));
        pthread_setspecific(stream_pkey, a);
    }
    return a;
}

inline LogStream* CreateLogStream(const PathChar* file, int line,
                                  LogSeverity severity) {
    int slot = 0;
    if (severity >= 0) {
        DCHECK_LT(severity, LOG_NUM_SEVERITIES);
        slot = severity + 1;
    } // else vlog
    LogStream** stream_array = get_or_new_tls_stream_array();
    LogStream* stream = stream_array[slot];
    if (stream == NULL) {
        stream = new LogStream;
        stream_array[slot] = stream;
    }
    if (stream->empty()) {
        stream->SetPosition(file, line, severity);
    }
    return stream;
}

inline void DestroyLogStream(LogStream* stream) {
    if (stream != NULL) {
        stream->Flush();
    }
}

class DefaultLogSink : public LogSink {
public:
    static DefaultLogSink* GetInstance() {
        return Singleton<DefaultLogSink,
                         LeakySingletonTraits<DefaultLogSink> >::get();
    }

    bool OnLogMessage(int severity, const char* file, int line,
                      const sgxbutil::StringPiece& content) override {
        // There's a copy here to concatenate prefix and content. Since
        // DefaultLogSink is hardly used right now, the copy is irrelevant.
        // A LogSink focused on performance should also be able to handle
        // non-continuous inputs which is a must to maximize performance.
        std::ostringstream os;
        print_log_prefix(os, severity, file, line);
        os.write(content.data(), content.size());
        os << '\n';
        std::string log = os.str();
        
        if ((logging_destination & LOG_TO_SYSTEM_DEBUG_LOG) != 0) {
            fwrite(log.data(), log.size(), 1, stderr);
            fflush(stderr);
        } else if (severity >= kAlwaysPrintErrorLevel) {
            // When we're only outputting to a log file, above a certain log level, we
            // should still output to stderr so that we can better detect and diagnose
            // problems with unit tests, especially on the buildbots.
            fwrite(log.data(), log.size(), 1, stderr);
            fflush(stderr);
        }

        // write to log file
        if ((logging_destination & LOG_TO_FILE) != 0) {
            // We can have multiple threads and/or processes, so try to prevent them
            // from clobbering each other's writes.
            // If the client app did not call InitLogging, and the lock has not
            // been created do it now. We do this on demand, but if two threads try
            // to do this at the same time, there will be a race condition to create
            // the lock. This is why InitLogging should be called from the main
            // thread at the beginning of execution.
            LoggingLock::Init(LOCK_LOG_FILE, NULL);
            LoggingLock logging_lock;
            if (InitializeLogFileHandle()) {
                fwrite(log.data(), log.size(), 1, log_file);
                fflush(log_file);
            }
        }
        return true;
    }
private:
    DefaultLogSink() {}
    ~DefaultLogSink() {}
friend struct DefaultSingletonTraits<DefaultLogSink>;
};

void LogStream::FlushWithoutReset() {
    if (empty()) {
        // Nothing to flush.
        return;
    }
    //- Don't use butil/debug/xxx code in sgx-braft.
    // if (FLAGS_print_stack_on_check && _is_check && _severity == BLOG_FATAL) {
    //     // Include a stack trace on a fatal.
    //     sgxbutil::debug::StackTrace trace;
    //     size_t count = 0;
    //     const void* const* addrs = trace.Addresses(&count);

    //     *this << std::endl;  // Newline to separate from log message.
    //     if (count > 3) {
    //         // Remove top 3 frames which are useless to users.
    //         // #2 may be ~LogStream
    //         //   #0 0x00000059ccae sgxbutil::debug::StackTrace::StackTrace()
    //         //   #1 0x0000005947c7 logging::LogStream::FlushWithoutReset()
    //         //   #2 0x000000594b88 logging::LogMessage::~LogMessage()
    //         sgxbutil::debug::StackTrace trace_stripped(addrs + 3, count - 3);
    //         trace_stripped.OutputToStream(this);
    //     } else {
    //         trace.OutputToStream(this);
    //     }
    // }
    
    // End the data with zero because sink is likely to assume this.
    *this << std::ends;
    // Move back one step because we don't want to count the zero.
    pbump(-1); 

    bool tried_default = false;
    {
        DoublyBufferedLogSink::ScopedPtr ptr;
        if (DoublyBufferedLogSink::GetInstance()->Read(&ptr) == 0 &&
            (*ptr) != NULL) {
            if ((*ptr)->OnLogMessage(_severity, _file, _line, content())) {
                goto FINISH_LOGGING;
            }
            tried_default = (*ptr == DefaultLogSink::GetInstance());
        }
    }

    if (!tried_default) {
        DefaultLogSink::GetInstance()->OnLogMessage(
            _severity, _file, _line, content());
    }

FINISH_LOGGING:
    return;
    //- Don't use butil/debug code in sgx-braft.
    // if (FLAGS_crash_on_fatal_log && _severity == BLOG_FATAL) {
    //     // Ensure the first characters of the string are on the stack so they
    //     // are contained in minidumps for diagnostic purposes.
    //     sgxbutil::StringPiece str = content();
    //     char str_stack[1024];
    //     str.copy(str_stack, arraysize(str_stack));
    //     sgxbutil::debug::Alias(str_stack);

    //     if (log_assert_handler) {
    //         // Make a copy of the string for the handler out of paranoia.
    //         log_assert_handler(str.as_string());
    //     } else {
    //         // Don't use the string with the newline, get a fresh version to send to
    //         // the debug message process. We also don't display assertions to the
    //         // user in release mode. The enduser can't do anything with this
    //         // information, and displaying message boxes when the application is
    //         // hosed can cause additional problems.

    //         // Crash the process to generate a dump.
    //         sgxbutil::debug::BreakDebugger();
    //     }
    // }
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity) {
    _stream = CreateLogStream(file, line, severity);
}

LogMessage::LogMessage(const char* file, int line, std::string* result) {
    _stream = CreateLogStream(file, line, BLOG_FATAL);
    *_stream << "Check failed: " << *result;
    delete result;
}

LogMessage::LogMessage(const char* file, int line, LogSeverity severity,
                       std::string* result) {
    _stream = CreateLogStream(file, line, severity);
    *_stream << "Check failed: " << *result;
    delete result;
}

LogMessage::~LogMessage() {
    DestroyLogStream(_stream);
}

SystemErrorCode GetLastSystemErrorCode() {
    return errno;
}

void SetLastSystemErrorCode(SystemErrorCode err) {
    errno = err;
}

BUTIL_EXPORT std::string SystemErrorCodeToString(SystemErrorCode error_code) {
    return berror(error_code);
}



ErrnoLogMessage::ErrnoLogMessage(const char* file,
                                 int line,
                                 LogSeverity severity,
                                 SystemErrorCode err)
    : err_(err),
      log_message_(file, line, severity) {
}

ErrnoLogMessage::~ErrnoLogMessage() {
    stream() << ": " << SystemErrorCodeToString(err_);
}

void CloseLogFile() {
    LoggingLock logging_lock;
    CloseLogFileUnlocked();
}

void RawLog(int level, const char* message) {
    if (level >= FLAGS_minloglevel) {
        size_t bytes_written = 0;
        const size_t message_len = strlen(message);
        int rv;
        while (bytes_written < message_len) {
            rv = HANDLE_EINTR(
                write(STDERR_FILENO, message + bytes_written,
                      message_len - bytes_written));
            if (rv < 0) {
                // Give up, nothing we can do now.
                break;
            }
            bytes_written += rv;
        }

        if (message_len > 0 && message[message_len - 1] != '\n') {
            do {
                rv = HANDLE_EINTR(write(STDERR_FILENO, "\n", 1));
                if (rv < 0) {
                    // Give up, nothing we can do now.
                    break;
                }
            } while (rv != 1);
        }
    }

    //- Don't use butil/debug code in sgx-braft.
    // if (FLAGS_crash_on_fatal_log && level == BLOG_FATAL)
    //     sgxbutil::debug::BreakDebugger();
}

// This was defined at the beginning of this file.
#undef write


// ----------- VLOG stuff -----------------
struct VLogSite;
struct VModuleList;

extern const int VLOG_UNINITIALIZED = std::numeric_limits<int>::max();

static pthread_mutex_t vlog_site_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static VLogSite* vlog_site_list = NULL;
static VModuleList* vmodule_list = NULL;

static pthread_mutex_t reset_vmodule_and_v_mutex = PTHREAD_MUTEX_INITIALIZER;

static const int64_t DELAY_DELETION_SEC = 10;
static std::deque<std::pair<VModuleList*, int64_t> >*
deleting_vmodule_list = NULL;

struct VLogSite {
    VLogSite(const char* filename, int required_v, int line_no)
        : _next(0), _v(0), _required_v(required_v), _line_no(line_no) {
        // Remove dirname/extname.
        sgxbutil::StringPiece s(filename);
        size_t pos = s.find_last_of("./");
        if (pos != sgxbutil::StringPiece::npos) {
            if (s[pos] == '.') {
                s.remove_suffix(s.size() - pos);
                _full_module.assign(s.data(), s.size());
                size_t pos2 = s.find_last_of('/');
                if (pos2 != sgxbutil::StringPiece::npos) {
                    s.remove_prefix(pos2 + 1);
                }
            } else {
                _full_module.assign(s.data(), s.size());
                s.remove_prefix(pos + 1);
            }
        } // else keep _full_module empty when it equals _module
        _module.assign(s.data(), s.size());
        std::transform(_module.begin(), _module.end(),
                       _module.begin(), ::tolower);
        if (!_full_module.empty()) {
            std::transform(_full_module.begin(), _full_module.end(),
                           _full_module.begin(), ::tolower);
        }
    }

    // The consume/release fence makes the iteration outside lock see
    // newly added VLogSite correctly.
    VLogSite* next() { return (VLogSite*)sgxbutil::subtle::Acquire_Load(&_next); }
    const VLogSite* next() const
    { return (VLogSite*)sgxbutil::subtle::Acquire_Load(&_next); }
    void set_next(VLogSite* next)
    { sgxbutil::subtle::Release_Store(&_next, (sgxbutil::subtle::AtomicWord)next); }

    int v() const { return _v; }
    int& v() { return _v; }

    int required_v() const { return  _required_v; }
    int line_no() const { return _line_no; }

    const std::string& module() const { return _module; }
    const std::string& full_module() const { return _full_module; }
    
private:
    // Next site in the list. NULL means no next.
    sgxbutil::subtle::AtomicWord _next;

    // --vmodule > --v
    int _v;
    
    // vlog is on iff _v >= _required_v
    int _required_v;

    // line nubmer of the vlog.
    int _line_no;
    
    // Lowered, dirname & extname removed.
    std::string _module;
    // Lowered, extname removed. Empty when it equals to _module.
    std::string _full_module;
};

// Written by Jack Handy
// <A href="mailto:jakkhandy@hotmail.com">jakkhandy@hotmail.com</A>
bool wildcmp(const char* wild, const char* str) {
    const char* cp = NULL;
    const char* mp = NULL;

    while (*str && *wild != '*') {
        if (*wild != *str && *wild != '?') {
            return false;
        }
        ++wild;
        ++str;
    }

    while (*str) {
        if (*wild == '*') {
            if (!*++wild) {
                return true;
            }
            mp = wild;
            cp = str+1;
        } else if (*wild == *str || *wild == '?') {
            ++wild;
            ++str;
        } else {
            wild = mp;
            str = cp++;
        }
    }

    while (*wild == '*') {
        ++wild;
    }
    return !*wild;
}

struct VModuleList {
    VModuleList() {}

    int init(const char* vmodules) {
        _exact_names.clear();
        _wild_names.clear();
                           
        for (sgxbutil::StringSplitter sp(vmodules, ','); sp; ++sp) {
            int verbose_level = std::numeric_limits<int>::max();
            size_t off = 0;
            for (; off < sp.length() && sp.field()[off] != '='; ++off) {}
            if (off + 1 < sp.length()) {
                verbose_level = strtol(sp.field() + off + 1, NULL, 10);
                
            }
            const char* name_begin = sp.field();
            const char* name_end = sp.field() + off - 1;
            for (; isspace(*name_begin) && name_begin < sp.field() + off;
                 ++name_begin) {}
            for (; isspace(*name_end) && name_end >= sp.field(); --name_end) {}
            
            if (name_begin > name_end) {  // only has spaces
                continue;
            }
            std::string name(name_begin, name_end - name_begin + 1);
            std::transform(name.begin(), name.end(), name.begin(), ::tolower);
            if (name.find_first_of("*?") == std::string::npos) {
                _exact_names[name] = verbose_level;
            } else {
                _wild_names.push_back(std::make_pair(name, verbose_level));
            }
        }
        // Reverse _wild_names so that latter wild cards override former ones.
        if (!_wild_names.empty()) {
            std::reverse(_wild_names.begin(), _wild_names.end());
        }
        return 0;
    }

    bool find_verbose_level(const std::string& module,
                            const std::string& full_module, int* v) const {
        if (!_exact_names.empty()) {
            std::map<std::string, int>::const_iterator
                it = _exact_names.find(module);
            if (it != _exact_names.end()) {
                *v = it->second;
                return true;
            }
            if (!full_module.empty()) {
                it = _exact_names.find(full_module);
                if (it != _exact_names.end()) {
                    *v = it->second;
                    return true;
                }
            }
        }

        for (size_t i = 0; i < _wild_names.size(); ++i) {
            if (wildcmp(_wild_names[i].first.c_str(), module.c_str())) {
                *v = _wild_names[i].second;
                return true;
            }
            if (!full_module.empty() &&
                wildcmp(_wild_names[i].first.c_str(), full_module.c_str())) {
                *v = _wild_names[i].second;
                return true;
            }
        }
        return false;
    }

    void print(std::ostream& os) const {
        os << "exact:";
        for (std::map<std::string, int>::const_iterator
                 it = _exact_names.begin(); it != _exact_names.end(); ++it) {
            os << ' ' << it->first << '=' << it->second;
        }
        os << ", wild:";
        for (size_t i = 0; i < _wild_names.size(); ++i) {
            os << ' ' << _wild_names[i].first << '=' << _wild_names[i].second;
        }
    }

private:
    std::map<std::string, int> _exact_names;
    std::vector<std::pair<std::string, int> > _wild_names;
};

// [ The idea ] 
// Each callsite creates a VLogSite and inserts the site into singly-linked
// vlog_site_list. To keep the critical area small, we use optimistic
// locking : Assign local site w/o locking, then insert the site into
// global list w/ locking, if local_module_list != global_vmodule_list or
// local_default_v != FLAGS_v, repeat the assigment.
// An important property of vlog_site_list is that: It does not remove sites.
// When we need to iterate the list, we don't have to hold the lock. What we
// do is to get the head of the list inside lock and iterate the list w/o
// lock. If new sites is inserted during the iteration, it should see and
// use the updated vmodule_list and FLAGS_v, nothing will be missed.

static int vlog_site_list_add(VLogSite* site,
                              VModuleList** expected_module_list,
                              int* expected_default_v) {
    BAIDU_SCOPED_LOCK(vlog_site_list_mutex);
    if (vmodule_list != *expected_module_list) {
        *expected_module_list = vmodule_list;
        return -1;
    }
    if (*expected_default_v != FLAGS_v) {
        *expected_default_v = FLAGS_v;
        return -1;
    }
    site->set_next(vlog_site_list);
    vlog_site_list = site;
    return 0;
}

bool add_vlog_site(const int** v, const char* filename, int line_no,
                   int required_v) {
    VLogSite* site = new (std::nothrow) VLogSite(filename, required_v, line_no);
    if (site == NULL) {
        return false;
    }
    VModuleList* module_list = vmodule_list;
    int default_v = FLAGS_v;
    do {
        site->v() = default_v;
        if (module_list) {
            module_list->find_verbose_level(
                site->module(), site->full_module(), &site->v());
        }
    } while (vlog_site_list_add(site, &module_list, &default_v) != 0);
    *v = &site->v();
    return site->v() >= required_v;
}

void print_vlog_sites(VLogSitePrinter* printer) {
    VLogSite* head = NULL;
    {
        BAIDU_SCOPED_LOCK(vlog_site_list_mutex);
        head = vlog_site_list;
    }
    VLogSitePrinter::Site site;
    for (const VLogSite* p = head; p; p = p->next()) {
        site.current_verbose_level = p->v();
        site.required_verbose_level = p->required_v();
        site.line_no = p->line_no();
        site.full_module = p->full_module();
        printer->print(site);
    }
}

// [Thread-safe] Reset FLAGS_vmodule.
static int on_reset_vmodule(const char* vmodule) {
    // resetting must be serialized.
    BAIDU_SCOPED_LOCK(reset_vmodule_and_v_mutex);
    
    VModuleList* module_list = new (std::nothrow) VModuleList;
    if (NULL == module_list) {
        LOG(FATAL) << "Fail to new VModuleList";
        return -1;
    }
    if (module_list->init(vmodule) != 0) {
        delete module_list;
        LOG(FATAL) << "Fail to init VModuleList";
        return -1;
    }
    
    VModuleList* old_module_list = NULL;
    VLogSite* old_vlog_site_list = NULL;
    {
        {
            BAIDU_SCOPED_LOCK(vlog_site_list_mutex);
            old_module_list = vmodule_list;
            vmodule_list = module_list;
            old_vlog_site_list = vlog_site_list;
        }
        for (VLogSite* p = old_vlog_site_list; p; p = p->next()) {
            p->v() = FLAGS_v;
            module_list->find_verbose_level(
                p->module(), p->full_module(), &p->v());
        }
    }
    
    if (old_module_list) {
        //delay the deletion.
        if (NULL == deleting_vmodule_list) {
            deleting_vmodule_list =
                new std::deque<std::pair<VModuleList*, int64_t> >;
        }
        deleting_vmodule_list->push_back(
            std::make_pair(old_module_list,
                           sgxbutil::gettimeofday_us() + DELAY_DELETION_SEC * 1000000L));
        while (!deleting_vmodule_list->empty() &&
               deleting_vmodule_list->front().second <= sgxbutil::gettimeofday_us()) {
            delete deleting_vmodule_list->front().first;
            deleting_vmodule_list->pop_front();
        }
    }
    return 0;
}

static bool validate_vmodule(const char*, const std::string& vmodule) {
    return on_reset_vmodule(vmodule.c_str()) == 0;
}

const bool ALLOW_UNUSED validate_vmodule_dummy = GFLAGS_NS::RegisterFlagValidator(
    &FLAGS_vmodule, &validate_vmodule);

// [Thread-safe] Reset FLAGS_v.
static void on_reset_verbose(int default_v) {
    VModuleList* cur_module_list = NULL;
    VLogSite* cur_vlog_site_list = NULL;
    {
        // resetting must be serialized.
        BAIDU_SCOPED_LOCK(reset_vmodule_and_v_mutex);
        {
            BAIDU_SCOPED_LOCK(vlog_site_list_mutex);
            cur_module_list = vmodule_list;
            cur_vlog_site_list = vlog_site_list;
        }
        for (VLogSite* p = cur_vlog_site_list; p; p = p->next()) {
            p->v() = default_v;
            if (cur_module_list) {
                cur_module_list->find_verbose_level(
                    p->module(), p->full_module(), &p->v());
            }
        }
    }
}

static bool validate_v(const char*, int32_t v) {
    on_reset_verbose(v);
    return true;
}

const bool ALLOW_UNUSED validate_v_dummy = GFLAGS_NS::RegisterFlagValidator(
    &FLAGS_v, &validate_v);

static bool PassValidate(const char*, bool) {
    return true;
}

const bool ALLOW_UNUSED validate_crash_on_fatal_log =
    GFLAGS_NS::RegisterFlagValidator(&FLAGS_crash_on_fatal_log, PassValidate);

const bool ALLOW_UNUSED validate_print_stack_on_check =
    GFLAGS_NS::RegisterFlagValidator(&FLAGS_print_stack_on_check, PassValidate);

static bool NonNegativeInteger(const char*, int32_t v) {
    return v >= 0;
}

const bool ALLOW_UNUSED validate_min_log_level = GFLAGS_NS::RegisterFlagValidator(
    &FLAGS_minloglevel, NonNegativeInteger);

}  // namespace logging

// std::ostream& operator<<(std::ostream& out, const wchar_t* wstr) {
//     return out << butil::WideToUTF8(std::wstring(wstr));
// }

#endif  // BRPC_WITH_GLOG
