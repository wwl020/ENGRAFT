#!/bin/bash
#===============================================================================
#
#          FILE:  stop.sh
# 
#         USAGE:  ./stop.sh 
# 
#   DESCRIPTION:  
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR:  WangYao (), wangyao02@baidu.com
#       COMPANY:  Baidu.com, Inc
#       VERSION:  1.0
#       CREATED:  2015年10月30日 17时50分43秒 CST
#      REVISION:  ---
#===============================================================================

# send KILL signal
killall -9 counter_server

# send Ctrl + C signal(sgx-braft developer custom choice)
# killall -2 counter_server
