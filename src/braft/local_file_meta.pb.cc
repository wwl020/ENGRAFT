// Generated by the protocol buffer compiler.  DO NOT EDIT!

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "braft/local_file_meta.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace braft {

namespace {

const ::google::protobuf::Descriptor* LocalFileMeta_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  LocalFileMeta_reflection_ = NULL;
const ::google::protobuf::EnumDescriptor* FileSource_descriptor_ = NULL;

}  // namespace


void protobuf_AssignDesc_braft_2flocal_5ffile_5fmeta_2eproto() {
  protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "braft/local_file_meta.proto");
  GOOGLE_CHECK(file != NULL);
  LocalFileMeta_descriptor_ = file->message_type(0);
  static const int LocalFileMeta_offsets_[3] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(LocalFileMeta, user_meta_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(LocalFileMeta, source_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(LocalFileMeta, checksum_),
  };
  LocalFileMeta_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      LocalFileMeta_descriptor_,
      LocalFileMeta::default_instance_,
      LocalFileMeta_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(LocalFileMeta, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(LocalFileMeta, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(LocalFileMeta));
  FileSource_descriptor_ = file->enum_type(0);
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_braft_2flocal_5ffile_5fmeta_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    LocalFileMeta_descriptor_, &LocalFileMeta::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_braft_2flocal_5ffile_5fmeta_2eproto() {
  delete LocalFileMeta::default_instance_;
  delete LocalFileMeta_reflection_;
}

void protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\033braft/local_file_meta.proto\022\005braft\"W\n\r"
    "LocalFileMeta\022\021\n\tuser_meta\030\001 \001(\014\022!\n\006sour"
    "ce\030\002 \001(\0162\021.braft.FileSource\022\020\n\010checksum\030"
    "\003 \001(\t*>\n\nFileSource\022\025\n\021FILE_SOURCE_LOCAL"
    "\020\000\022\031\n\025FILE_SOURCE_REFERENCE\020\001", 189);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "braft/local_file_meta.proto", &protobuf_RegisterTypes);
  LocalFileMeta::default_instance_ = new LocalFileMeta();
  LocalFileMeta::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_braft_2flocal_5ffile_5fmeta_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_braft_2flocal_5ffile_5fmeta_2eproto {
  StaticDescriptorInitializer_braft_2flocal_5ffile_5fmeta_2eproto() {
    protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto();
  }
} static_descriptor_initializer_braft_2flocal_5ffile_5fmeta_2eproto_;

const ::google::protobuf::EnumDescriptor* FileSource_descriptor() {
  protobuf_AssignDescriptorsOnce();
  return FileSource_descriptor_;
}
bool FileSource_IsValid(int value) {
  switch(value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}


// ===================================================================

#ifndef _MSC_VER
const int LocalFileMeta::kUserMetaFieldNumber;
const int LocalFileMeta::kSourceFieldNumber;
const int LocalFileMeta::kChecksumFieldNumber;
#endif  // !_MSC_VER

LocalFileMeta::LocalFileMeta()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void LocalFileMeta::InitAsDefaultInstance() {
}

LocalFileMeta::LocalFileMeta(const LocalFileMeta& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void LocalFileMeta::SharedCtor() {
  _cached_size_ = 0;
  user_meta_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  source_ = 0;
  checksum_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

LocalFileMeta::~LocalFileMeta() {
  SharedDtor();
}

void LocalFileMeta::SharedDtor() {
  if (user_meta_ != &::google::protobuf::internal::kEmptyString) {
    delete user_meta_;
  }
  if (checksum_ != &::google::protobuf::internal::kEmptyString) {
    delete checksum_;
  }
  if (this != default_instance_) {
  }
}

void LocalFileMeta::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* LocalFileMeta::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return LocalFileMeta_descriptor_;
}

const LocalFileMeta& LocalFileMeta::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_braft_2flocal_5ffile_5fmeta_2eproto();  return *default_instance_;
}

LocalFileMeta* LocalFileMeta::default_instance_ = NULL;

LocalFileMeta* LocalFileMeta::New() const {
  return new LocalFileMeta;
}

void LocalFileMeta::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (has_user_meta()) {
      if (user_meta_ != &::google::protobuf::internal::kEmptyString) {
        user_meta_->clear();
      }
    }
    source_ = 0;
    if (has_checksum()) {
      if (checksum_ != &::google::protobuf::internal::kEmptyString) {
        checksum_->clear();
      }
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool LocalFileMeta::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // optional bytes user_meta = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadBytes(
                input, this->mutable_user_meta()));
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(16)) goto parse_source;
        break;
      }
      
      // optional .braft.FileSource source = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_source:
          int value;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          if (braft::FileSource_IsValid(value)) {
            set_source(static_cast< braft::FileSource >(value));
          } else {
            mutable_unknown_fields()->AddVarint(2, value);
          }
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(26)) goto parse_checksum;
        break;
      }
      
      // optional string checksum = 3;
      case 3: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_checksum:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_checksum()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->checksum().data(), this->checksum().length(),
            ::google::protobuf::internal::WireFormat::PARSE);
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectAtEnd()) return true;
        break;
      }
      
      default: {
      handle_uninterpreted:
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
          return true;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, mutable_unknown_fields()));
        break;
      }
    }
  }
  return true;
#undef DO_
}

void LocalFileMeta::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // optional bytes user_meta = 1;
  if (has_user_meta()) {
    ::google::protobuf::internal::WireFormatLite::WriteBytes(
      1, this->user_meta(), output);
  }
  
  // optional .braft.FileSource source = 2;
  if (has_source()) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      2, this->source(), output);
  }
  
  // optional string checksum = 3;
  if (has_checksum()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->checksum().data(), this->checksum().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      3, this->checksum(), output);
  }
  
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* LocalFileMeta::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // optional bytes user_meta = 1;
  if (has_user_meta()) {
    target =
      ::google::protobuf::internal::WireFormatLite::WriteBytesToArray(
        1, this->user_meta(), target);
  }
  
  // optional .braft.FileSource source = 2;
  if (has_source()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteEnumToArray(
      2, this->source(), target);
  }
  
  // optional string checksum = 3;
  if (has_checksum()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->checksum().data(), this->checksum().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        3, this->checksum(), target);
  }
  
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int LocalFileMeta::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // optional bytes user_meta = 1;
    if (has_user_meta()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::BytesSize(
          this->user_meta());
    }
    
    // optional .braft.FileSource source = 2;
    if (has_source()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::EnumSize(this->source());
    }
    
    // optional string checksum = 3;
    if (has_checksum()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->checksum());
    }
    
  }
  if (!unknown_fields().empty()) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        unknown_fields());
  }
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = total_size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
  return total_size;
}

void LocalFileMeta::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const LocalFileMeta* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const LocalFileMeta*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void LocalFileMeta::MergeFrom(const LocalFileMeta& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_user_meta()) {
      set_user_meta(from.user_meta());
    }
    if (from.has_source()) {
      set_source(from.source());
    }
    if (from.has_checksum()) {
      set_checksum(from.checksum());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void LocalFileMeta::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void LocalFileMeta::CopyFrom(const LocalFileMeta& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool LocalFileMeta::IsInitialized() const {
  
  return true;
}

void LocalFileMeta::Swap(LocalFileMeta* other) {
  if (other != this) {
    std::swap(user_meta_, other->user_meta_);
    std::swap(source_, other->source_);
    std::swap(checksum_, other->checksum_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata LocalFileMeta::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = LocalFileMeta_descriptor_;
  metadata.reflection = LocalFileMeta_reflection_;
  return metadata;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace braft

// @@protoc_insertion_point(global_scope)
