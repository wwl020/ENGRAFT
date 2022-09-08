// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: braft/local_file_meta.proto

#ifndef PROTOBUF_braft_2flocal_5ffile_5fmeta_2eproto__INCLUDED
#define PROTOBUF_braft_2flocal_5ffile_5fmeta_2eproto__INCLUDED

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
void  protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto();
void protobuf_AssignDesc_braft_2flocal_5ffile_5fmeta_2eproto();
void protobuf_ShutdownFile_braft_2flocal_5ffile_5fmeta_2eproto();

class LocalFileMeta;

enum FileSource {
  FILE_SOURCE_LOCAL = 0,
  FILE_SOURCE_REFERENCE = 1
};
bool FileSource_IsValid(int value);
const FileSource FileSource_MIN = FILE_SOURCE_LOCAL;
const FileSource FileSource_MAX = FILE_SOURCE_REFERENCE;
const int FileSource_ARRAYSIZE = FileSource_MAX + 1;

const ::google::protobuf::EnumDescriptor* FileSource_descriptor();
inline const ::std::string& FileSource_Name(FileSource value) {
  return ::google::protobuf::internal::NameOfEnum(
    FileSource_descriptor(), value);
}
inline bool FileSource_Parse(
    const ::std::string& name, FileSource* value) {
  return ::google::protobuf::internal::ParseNamedEnum<FileSource>(
    FileSource_descriptor(), name, value);
}
// ===================================================================

class LocalFileMeta : public ::google::protobuf::Message {
 public:
  LocalFileMeta();
  virtual ~LocalFileMeta();
  
  LocalFileMeta(const LocalFileMeta& from);
  
  inline LocalFileMeta& operator=(const LocalFileMeta& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const LocalFileMeta& default_instance();
  
  void Swap(LocalFileMeta* other);
  
  // implements Message ----------------------------------------------
  
  LocalFileMeta* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const LocalFileMeta& from);
  void MergeFrom(const LocalFileMeta& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // optional bytes user_meta = 1;
  inline bool has_user_meta() const;
  inline void clear_user_meta();
  static const int kUserMetaFieldNumber = 1;
  inline const ::std::string& user_meta() const;
  inline void set_user_meta(const ::std::string& value);
  inline void set_user_meta(const char* value);
  inline void set_user_meta(const void* value, size_t size);
  inline ::std::string* mutable_user_meta();
  inline ::std::string* release_user_meta();
  
  // optional .braft.FileSource source = 2;
  inline bool has_source() const;
  inline void clear_source();
  static const int kSourceFieldNumber = 2;
  inline braft::FileSource source() const;
  inline void set_source(braft::FileSource value);
  
  // optional string checksum = 3;
  inline bool has_checksum() const;
  inline void clear_checksum();
  static const int kChecksumFieldNumber = 3;
  inline const ::std::string& checksum() const;
  inline void set_checksum(const ::std::string& value);
  inline void set_checksum(const char* value);
  inline void set_checksum(const char* value, size_t size);
  inline ::std::string* mutable_checksum();
  inline ::std::string* release_checksum();
  
  // @@protoc_insertion_point(class_scope:braft.LocalFileMeta)
 private:
  inline void set_has_user_meta();
  inline void clear_has_user_meta();
  inline void set_has_source();
  inline void clear_has_source();
  inline void set_has_checksum();
  inline void clear_has_checksum();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::std::string* user_meta_;
  ::std::string* checksum_;
  int source_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(3 + 31) / 32];
  
  friend void  protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto();
  friend void protobuf_AssignDesc_braft_2flocal_5ffile_5fmeta_2eproto();
  friend void protobuf_ShutdownFile_braft_2flocal_5ffile_5fmeta_2eproto();
  
  void InitAsDefaultInstance();
  static LocalFileMeta* default_instance_;
};
// ===================================================================


// ===================================================================

// LocalFileMeta

// optional bytes user_meta = 1;
inline bool LocalFileMeta::has_user_meta() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void LocalFileMeta::set_has_user_meta() {
  _has_bits_[0] |= 0x00000001u;
}
inline void LocalFileMeta::clear_has_user_meta() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void LocalFileMeta::clear_user_meta() {
  if (user_meta_ != &::google::protobuf::internal::kEmptyString) {
    user_meta_->clear();
  }
  clear_has_user_meta();
}
inline const ::std::string& LocalFileMeta::user_meta() const {
  return *user_meta_;
}
inline void LocalFileMeta::set_user_meta(const ::std::string& value) {
  set_has_user_meta();
  if (user_meta_ == &::google::protobuf::internal::kEmptyString) {
    user_meta_ = new ::std::string;
  }
  user_meta_->assign(value);
}
inline void LocalFileMeta::set_user_meta(const char* value) {
  set_has_user_meta();
  if (user_meta_ == &::google::protobuf::internal::kEmptyString) {
    user_meta_ = new ::std::string;
  }
  user_meta_->assign(value);
}
inline void LocalFileMeta::set_user_meta(const void* value, size_t size) {
  set_has_user_meta();
  if (user_meta_ == &::google::protobuf::internal::kEmptyString) {
    user_meta_ = new ::std::string;
  }
  user_meta_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* LocalFileMeta::mutable_user_meta() {
  set_has_user_meta();
  if (user_meta_ == &::google::protobuf::internal::kEmptyString) {
    user_meta_ = new ::std::string;
  }
  return user_meta_;
}
inline ::std::string* LocalFileMeta::release_user_meta() {
  clear_has_user_meta();
  if (user_meta_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = user_meta_;
    user_meta_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}

// optional .braft.FileSource source = 2;
inline bool LocalFileMeta::has_source() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void LocalFileMeta::set_has_source() {
  _has_bits_[0] |= 0x00000002u;
}
inline void LocalFileMeta::clear_has_source() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void LocalFileMeta::clear_source() {
  source_ = 0;
  clear_has_source();
}
inline braft::FileSource LocalFileMeta::source() const {
  return static_cast< braft::FileSource >(source_);
}
inline void LocalFileMeta::set_source(braft::FileSource value) {
  GOOGLE_DCHECK(braft::FileSource_IsValid(value));
  set_has_source();
  source_ = value;
}

// optional string checksum = 3;
inline bool LocalFileMeta::has_checksum() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void LocalFileMeta::set_has_checksum() {
  _has_bits_[0] |= 0x00000004u;
}
inline void LocalFileMeta::clear_has_checksum() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void LocalFileMeta::clear_checksum() {
  if (checksum_ != &::google::protobuf::internal::kEmptyString) {
    checksum_->clear();
  }
  clear_has_checksum();
}
inline const ::std::string& LocalFileMeta::checksum() const {
  return *checksum_;
}
inline void LocalFileMeta::set_checksum(const ::std::string& value) {
  set_has_checksum();
  if (checksum_ == &::google::protobuf::internal::kEmptyString) {
    checksum_ = new ::std::string;
  }
  checksum_->assign(value);
}
inline void LocalFileMeta::set_checksum(const char* value) {
  set_has_checksum();
  if (checksum_ == &::google::protobuf::internal::kEmptyString) {
    checksum_ = new ::std::string;
  }
  checksum_->assign(value);
}
inline void LocalFileMeta::set_checksum(const char* value, size_t size) {
  set_has_checksum();
  if (checksum_ == &::google::protobuf::internal::kEmptyString) {
    checksum_ = new ::std::string;
  }
  checksum_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* LocalFileMeta::mutable_checksum() {
  set_has_checksum();
  if (checksum_ == &::google::protobuf::internal::kEmptyString) {
    checksum_ = new ::std::string;
  }
  return checksum_;
}
inline ::std::string* LocalFileMeta::release_checksum() {
  clear_has_checksum();
  if (checksum_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = checksum_;
    checksum_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace braft

#ifndef SWIG
namespace google {
namespace protobuf {

template <>
inline const EnumDescriptor* GetEnumDescriptor< braft::FileSource>() {
  return braft::FileSource_descriptor();
}

}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_braft_2flocal_5ffile_5fmeta_2eproto__INCLUDED
