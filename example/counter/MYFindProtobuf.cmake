message(DEBUG "HELLO FROM FINDROTOBUF.CMAKE")
set(PROTOC_FLAGS "-I/home/jetli/sgx-learning/project/protobuf-2.4.1/installed/include" CACHE INTERNAL "")
set(PROTOBUF_PROTOC_EXECUTABLE "/home/jetli/sgx-learning/project/protobuf-2.4.1/installed/bin/protoc" CACHE INTERNAL "")

function(compile_proto_2 OUT_HDRS OUT_SRCS DESTDIR PROTO_DIR PROTO_FILES)
  foreach(P ${PROTO_FILES})
    # string(REPLACE <match-string> <replace-string> <out-var> <input>...)
    # Replace all occurrences of <match_string> in the <input> with <replace_string> 
    # and store the result in the <output_variable>.
    string(REPLACE .proto .pb.h HDR ${P})
    set(HDR_RELATIVE ${HDR})
    set(HDR ${DESTDIR}/${HDR})
    string(REPLACE .proto .pb.cc SRC ${P})
    set(SRC ${DESTDIR}/${SRC})
    list(APPEND HDRS ${HDR})
    list(APPEND SRCS ${SRC})
    # This custom command compile the .proto file to header(.h) and source(.cc) files
    # Note that the header(.h) and source(.cc) files are compiled in {DESTDIR}
    # ${PROTO_DIR}/${P} denotes the proto files
    add_custom_command(
      OUTPUT ${HDR} ${SRC}
      COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${PROTOC_FLAGS} -I${PROTO_DIR} --cpp_out=${DESTDIR} ${PROTO_DIR}/${P}
    )
    # added for debug
    # message(STATUS "PROTOBUF_PROTOC_EXECUTABLE: ${PROTOBUF_PROTOC_EXECUTABLE}")
  endforeach()
  set(${OUT_HDRS} ${HDRS} PARENT_SCOPE)
  set(${OUT_SRCS} ${SRCS} PARENT_SCOPE)
endfunction()