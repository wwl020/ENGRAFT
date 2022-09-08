message(host::CMAKE_CURRENT_SOURCE_DIR:${CMAKE_CURRENT_SOURCE_DIR})
message(host::CMAKE_SOURCE_DIR:${CMAKE_SOURCE_DIR})
message(host::CMAKE_CURRENT_BINARY_DIR:${CMAKE_CURRENT_BINARY_DIR})

SET(HOST_SRC host_utils.cpp
             entry.cpp
             host_event_dis.cpp
             host_tpm_utils.cpp)

# debug symbol
set(CMAKE_CPP_FLAGS "${CMAKE_CPP_FLAGS} -g")

add_custom_command(
  OUTPUT interface_u.h interface_u.c interface_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/interface.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/interface.edl
    --search-path ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

file(GLOB_RECURSE UTILS_SRC "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.cpp" 
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/*.c" )

add_executable(sgx_raft_host ${HOST_SRC} 
                             ${UTILS_SRC}
                             ${CMAKE_CURRENT_BINARY_DIR}/interface_u.c)

include_directories("/usr/local/include/tss2")
include_directories(${CMAKE_SOURCE_DIR}/src)

target_include_directories(
    sgx_raft_host PRIVATE # Needed for the generated file interface_u.h
                          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sgx_raft_host   openenclave::oehost 
                                      ssl
                                      crypto
                                      gflags)