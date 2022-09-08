# trash *(D) && cmake -DCMAKE_BUILD_TYPE=Debug .. && make -j16
cmake_minimum_required(VERSION 3.11)

# Comment out the clang code since we want to use gcc compiler.
# if (LVI_MITIGATION MATCHES ControlFlow)
#   # Configure the cmake to use customized compilation toolchain.
#   # This package has to be added before `project()`.
#   find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
# else ()
#   # Setting the cmake compiler when LVI mitigation is not enabled. If the CC
#   # environment variable has been specified or the if CMAKE_C_COMPILER cmake
#   # variable has been passed to cmake, use the C compiler that has been specified.
#   # Otherwise, prefer clang. Same for C++ compiler. This must be done before
#   # the `project` command.
#   if (UNIX)
#     if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
#       find_program(CMAKE_C_COMPILER clang-8 clang)
#     endif ()
#     if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
#       find_program(CMAKE_CXX_COMPILER clang++-8 clang++)
#     endif ()
#   endif ()
# endif ()


project("SGX-Braft version 0.06" LANGUAGES C CXX)
# option(TESTIF "test" OFF)
# if(TESTIF)
# message("true")
# else()
# message("false")
# endif()
add_compile_definitions(USE_HOST_EVENT_DISPATCHER)
add_compile_definitions(SGX_USE_REMOTE_ATTESTATION)
message(cpp_compiler: ${CMAKE_CXX_COMPILER})
message(c_compiler: ${CMAKE_C_COMPILER})

# Use ccache to boost compilation
set(CMAKE_CXX_COMPILER_LAUNCHER ccache)
set(CMAKE_C_COMPILER_LAUNCHER ccache)

#- Generate compile commands used by clangd.
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
# Set build type to debug to use oegdb
set(CMAKE_BUILD_TYPE Debug)
# set(CMAKE_BUILD_TYPE Release)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    openssl
    CACHE STRING "Crypto library used by enclaves.")

# enclave code
add_subdirectory(example/counter)
# host code
add_subdirectory(src/host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT example/counter/enclave.signed
  DEPENDS enclave example/counter/sgx_raft.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/example/counter/sgx_raft.conf -k private.pem)

add_custom_target(sign ALL DEPENDS example/counter/enclave.signed)

add_custom_target(
run
DEPENDS sgx_raft_host sign
COMMAND sgx_raft_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
