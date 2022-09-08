#!/bin/bash

# 用于上云测试跑在SGX外面的ENGRAFT，也可用在本地XPS分布式集群测试，通过 --port xxxx指定Raft端口为xxxx
# 可以取代原来的 server_run.sh

# source shflags from current directory
mydir="${BASH_SOURCE%/*}"
if [[ ! -d "$mydir" ]]; then mydir="$PWD"; fi
. $mydir/../shflags

# define command-line flags
DEFINE_string crash_on_fatal 'false' 'Crash on fatal log'
DEFINE_integer bthread_concurrency '8' 'Number of worker pthreads'
DEFINE_string sync 'true' 'fsync each time'
DEFINE_string valgrind 'false' 'Run in valgrind'
# 1073741824 = 1GB, 4000w log entries
DEFINE_integer max_segment_size '1073741824' 'Max segment size'
# 0: Clean the last runtime, 1: Do not clean
DEFINE_boolean clean 0 'Remove old "runtime" dir before running'
# 0: Run in background, 1: Run in foreground
# ./cluster_run --run_bg --port=8100
# --norun_bg
DEFINE_boolean run_bg 0 'Run servers in background'
DEFINE_integer port 8100 "Port of the first server"

# parse the command-line
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# The alias for printing to stderr
alias error=">&2 echo counter: "

if [ "$FLAGS_valgrind" == "true" ] && [ $(which valgrind) ] ; then
    VALGRIND="valgrind --tool=memcheck --leak-check=full"
fi

raft_peers="10.16.27.210:8100:0,10.16.38.212:8101:0,10.16.38.109:8102:0,"
raft_peers="101.132.105.173:8100:0,114.55.126.87:8101:0,39.106.71.12:8102:0,101.132.139.135:8103:0,47.97.173.53:8104:0,"

if [ "$FLAGS_clean" == "0" ]; then
    rm -rf runtime
fi

i=$[FLAGS_port-8100]
echo "i=${i}"
mkdir -p runtime/$i
cp ./counter_server runtime/$i
cd runtime/$i
if [ "$FLAGS_run_bg" == "1" ]; then
    ${VALGRIND} ./counter_server \
    -bthread_concurrency=${FLAGS_bthread_concurrency}\
    -crash_on_fatal_log=${FLAGS_crash_on_fatal} \
    -raft_max_segment_size=${FLAGS_max_segment_size} \
    -raft_sync=${FLAGS_sync} \
    -port=${FLAGS_port} -conf="${raft_peers}" 2>&1|tee std.log
    cd ../..
else
    ${VALGRIND} ./counter_server \
    -bthread_concurrency=${FLAGS_bthread_concurrency}\
    -crash_on_fatal_log=${FLAGS_crash_on_fatal} \
    -raft_max_segment_size=${FLAGS_max_segment_size} \
    -raft_sync=${FLAGS_sync} \
    -port=${FLAGS_port} -conf="${raft_peers}" > std.log 2>&1 &
    cd ../..
fi


