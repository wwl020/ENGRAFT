// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: braft/enum.proto

#ifndef PROTOBUF_braft_2fenum_2eproto__INCLUDED
#define PROTOBUF_braft_2fenum_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2004000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2004001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
// @@protoc_insertion_point(includes)

namespace braft {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_braft_2fenum_2eproto();
void protobuf_AssignDesc_braft_2fenum_2eproto();
void protobuf_ShutdownFile_braft_2fenum_2eproto();


enum EntryType {
  ENTRY_TYPE_UNKNOWN = 0,
  ENTRY_TYPE_NO_OP = 1,
  ENTRY_TYPE_DATA = 2,
  ENTRY_TYPE_CONFIGURATION = 3
};
bool EntryType_IsValid(int value);
const EntryType EntryType_MIN = ENTRY_TYPE_UNKNOWN;
const EntryType EntryType_MAX = ENTRY_TYPE_CONFIGURATION;
const int EntryType_ARRAYSIZE = EntryType_MAX + 1;

const ::google::protobuf::EnumDescriptor* EntryType_descriptor();
inline const ::std::string& EntryType_Name(EntryType value) {
  return ::google::protobuf::internal::NameOfEnum(
    EntryType_descriptor(), value);
}
inline bool EntryType_Parse(
    const ::std::string& name, EntryType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<EntryType>(
    EntryType_descriptor(), name, value);
}
enum ErrorType {
  ERROR_TYPE_NONE = 0,
  ERROR_TYPE_LOG = 1,
  ERROR_TYPE_STABLE = 2,
  ERROR_TYPE_SNAPSHOT = 3,
  ERROR_TYPE_STATE_MACHINE = 4
};
bool ErrorType_IsValid(int value);
const ErrorType ErrorType_MIN = ERROR_TYPE_NONE;
const ErrorType ErrorType_MAX = ERROR_TYPE_STATE_MACHINE;
const int ErrorType_ARRAYSIZE = ErrorType_MAX + 1;

const ::google::protobuf::EnumDescriptor* ErrorType_descriptor();
inline const ::std::string& ErrorType_Name(ErrorType value) {
  return ::google::protobuf::internal::NameOfEnum(
    ErrorType_descriptor(), value);
}
inline bool ErrorType_Parse(
    const ::std::string& name, ErrorType* value) {
  return ::google::protobuf::internal::ParseNamedEnum<ErrorType>(
    ErrorType_descriptor(), name, value);
}
// ===================================================================


// ===================================================================


// ===================================================================


// @@protoc_insertion_point(namespace_scope)

}  // namespace braft

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< braft::EntryType>() {
  return braft::EntryType_descriptor();
}
template <>
inline const EnumDescriptor* GetEnumDescriptor< braft::ErrorType>() {
  return braft::ErrorType_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_braft_2fenum_2eproto__INCLUDED