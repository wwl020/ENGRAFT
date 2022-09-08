#!/bin/bash

while getopts "abcd:" arg #选项后面的冒号表示该选项需要参数
do
        case $arg in
             a)                
                echo "SGX-Raft run outside enclaves"
                datestr=`date +%m%d-%H:%M:%S`
                mv CMakeLists.txt CMakeLists.txt."$datestr"
                cp CMakeLists_NoSGX.txt CMakeLists.txt

                enclave_cmake="example/counter"
                mv "$enclave_cmake"/CMakeLists.txt "$enclave_cmake"/CMakeLists.txt."$datestr"
                cp "$enclave_cmake"/CMakeLists_NoSGX.txt "$enclave_cmake"/CMakeLists.txt
                ;;
             b)
                echo "SGX-Raft run inside enclaves"
                datestr=`date +%m%d-%H:%M:%S`
                mv CMakeLists.txt CMakeLists.txt."$datestr"
                cp CMakeLists_SGX.txt CMakeLists.txt

                enclave_cmake="example/counter"
                mv "$enclave_cmake"/CMakeLists.txt "$enclave_cmake"/CMakeLists.txt."$datestr"
                cp "$enclave_cmake"/CMakeLists_SGX.txt "$enclave_cmake"/CMakeLists.txt
                ;;
             c)                
                echo "No imple..."  
                ;;                
             d)
                echo "c's arg:$OPTARG" #参数存在$OPTARG中
                ;;
             ?)  #当有不认识的选项的时候arg为?
            echo "unknow argument"
        exit 1
        ;;
        esac
done

# rm -rf build/*
# cd build
# cmake .. && make -j16
# cd ..