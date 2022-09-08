message(Enc::CMAKE_CURRENT_SOURCE_DIR:${CMAKE_CURRENT_SOURCE_DIR})
message(Enc::CMAKE_SOURCE_DIR:${CMAKE_SOURCE_DIR})
message(Enc::CMAKE_CURRENT_BINARY_DIR:${CMAKE_CURRENT_BINARY_DIR})

# braft counter server
SET(ENC_SRC server.cpp counter.pb.cc)

# debug symbol
# set(CMAKE_CPP_FLAGS "${CMAKE_CPP_FLAGS} -g")

add_compile_definitions(GFLAGS_NS=google)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT interface_t.h interface_t.c interface_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/interface.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/interface.edl
    --search-path ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

include_directories(${CMAKE_SOURCE_DIR}/src)

file(GLOB_RECURSE PROTOBUF_SRC "${CMAKE_SOURCE_DIR}/src/google/protobuf/*.cc")
file(GLOB_RECURSE GFLAGS_SRC "${CMAKE_SOURCE_DIR}/src/google/gflags/*.cc")
file(GLOB_RECURSE BRPC_SRC "${CMAKE_SOURCE_DIR}/src/brpc/*.cc"
                           "${CMAKE_SOURCE_DIR}/src/brpc/*.cpp")
file(GLOB_RECURSE SGXBUTIL_SRC "${CMAKE_SOURCE_DIR}/src/sgxbutil/*.cc"
                               "${CMAKE_SOURCE_DIR}/src/sgxbutil/*.cpp"
                               "${CMAKE_SOURCE_DIR}/src/sgxbutil/*.c" )
file(GLOB_RECURSE BRAFT_SRC "${CMAKE_SOURCE_DIR}/src/braft/*.cc"
                               "${CMAKE_SOURCE_DIR}/src/braft/*.cpp" )
file(GLOB_RECURSE BTHREAD_SRC "${CMAKE_SOURCE_DIR}/src/bthread/*.cc"
                               "${CMAKE_SOURCE_DIR}/src/bthread/*.cpp" )
file(GLOB_RECURSE SWITCHLESS_SRC "${CMAKE_SOURCE_DIR}/src/switchless/*.cpp")

add_executable(enclave ${ENC_SRC} 
                       ${BTHREAD_SRC}
                       ${BRAFT_SRC}
                       ${BRPC_SRC}
                       ${GFLAGS_SRC} 
                       ${PROTOBUF_SRC} 
                       ${SGXBUTIL_SRC}
                       ${SWITCHLESS_SRC}
                       ${CMAKE_CURRENT_BINARY_DIR}/interface_t.c)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file interface_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (LVI_MITIGATION MATCHES ControlFlow)
  # Helper to enable compiler options for LVI mitigation.
  apply_lvi_mitigation(enclave)
  # Link against LVI-mitigated libraries.
  target_link_libraries(
    enclave openenclave::oeenclave-lvi-cfg
    openenclave::oecrypto${OE_CRYPTO_LIB}-lvi-cfg openenclave::oelibc-lvi-cfg)
else ()
  target_link_libraries(
    enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
    # Specify pluggable allocator library
    # openenclave::oesnmalloc
    openenclave::oelibc
    # To support C++ in enclaves
    openenclave::oelibcxx
    openenclave::oehostsock
    openenclave::oehostfs
    # For epoll syscall
    openenclave::oehostepoll
    openenclave::oehostresolver)
endif ()