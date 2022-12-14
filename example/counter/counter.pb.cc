// Generated by the protocol buffer compiler.  DO NOT EDIT!

#define INTERNAL_SUPPRESS_PROTOBUF_FIELD_DEPRECATION
#include "counter.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)

namespace example {

namespace {

const ::google::protobuf::Descriptor* Snapshot_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  Snapshot_reflection_ = NULL;
const ::google::protobuf::Descriptor* FetchAddRequest_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  FetchAddRequest_reflection_ = NULL;
const ::google::protobuf::Descriptor* CounterResponse_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  CounterResponse_reflection_ = NULL;
const ::google::protobuf::Descriptor* GetRequest_descriptor_ = NULL;
const ::google::protobuf::internal::GeneratedMessageReflection*
  GetRequest_reflection_ = NULL;
const ::google::protobuf::ServiceDescriptor* CounterService_descriptor_ = NULL;

}  // namespace


void protobuf_AssignDesc_counter_2eproto() {
  protobuf_AddDesc_counter_2eproto();
  const ::google::protobuf::FileDescriptor* file =
    ::google::protobuf::DescriptorPool::generated_pool()->FindFileByName(
      "counter.proto");
  GOOGLE_CHECK(file != NULL);
  Snapshot_descriptor_ = file->message_type(0);
  static const int Snapshot_offsets_[1] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Snapshot, value_),
  };
  Snapshot_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      Snapshot_descriptor_,
      Snapshot::default_instance_,
      Snapshot_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Snapshot, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(Snapshot, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(Snapshot));
  FetchAddRequest_descriptor_ = file->message_type(1);
  static const int FetchAddRequest_offsets_[2] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FetchAddRequest, value_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FetchAddRequest, dummy_padding_),
  };
  FetchAddRequest_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      FetchAddRequest_descriptor_,
      FetchAddRequest::default_instance_,
      FetchAddRequest_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FetchAddRequest, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(FetchAddRequest, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(FetchAddRequest));
  CounterResponse_descriptor_ = file->message_type(2);
  static const int CounterResponse_offsets_[3] = {
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CounterResponse, success_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CounterResponse, value_),
    GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CounterResponse, redirect_),
  };
  CounterResponse_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      CounterResponse_descriptor_,
      CounterResponse::default_instance_,
      CounterResponse_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CounterResponse, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(CounterResponse, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(CounterResponse));
  GetRequest_descriptor_ = file->message_type(3);
  static const int GetRequest_offsets_[1] = {
  };
  GetRequest_reflection_ =
    new ::google::protobuf::internal::GeneratedMessageReflection(
      GetRequest_descriptor_,
      GetRequest::default_instance_,
      GetRequest_offsets_,
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(GetRequest, _has_bits_[0]),
      GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(GetRequest, _unknown_fields_),
      -1,
      ::google::protobuf::DescriptorPool::generated_pool(),
      ::google::protobuf::MessageFactory::generated_factory(),
      sizeof(GetRequest));
  CounterService_descriptor_ = file->service(0);
}

namespace {

GOOGLE_PROTOBUF_DECLARE_ONCE(protobuf_AssignDescriptors_once_);
inline void protobuf_AssignDescriptorsOnce() {
  ::google::protobuf::GoogleOnceInit(&protobuf_AssignDescriptors_once_,
                 &protobuf_AssignDesc_counter_2eproto);
}

void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    Snapshot_descriptor_, &Snapshot::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    FetchAddRequest_descriptor_, &FetchAddRequest::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    CounterResponse_descriptor_, &CounterResponse::default_instance());
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedMessage(
    GetRequest_descriptor_, &GetRequest::default_instance());
}

}  // namespace

void protobuf_ShutdownFile_counter_2eproto() {
  delete Snapshot::default_instance_;
  delete Snapshot_reflection_;
  delete FetchAddRequest::default_instance_;
  delete FetchAddRequest_reflection_;
  delete CounterResponse::default_instance_;
  delete CounterResponse_reflection_;
  delete GetRequest::default_instance_;
  delete GetRequest_reflection_;
}

void protobuf_AddDesc_counter_2eproto() {
  static bool already_here = false;
  if (already_here) return;
  already_here = true;
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
    "\n\rcounter.proto\022\007example\"\031\n\010Snapshot\022\r\n\005"
    "value\030\001 \002(\003\"7\n\017FetchAddRequest\022\r\n\005value\030"
    "\001 \002(\003\022\025\n\rdummy_padding\030\002 \001(\t\"C\n\017CounterR"
    "esponse\022\017\n\007success\030\001 \002(\010\022\r\n\005value\030\002 \001(\003\022"
    "\020\n\010redirect\030\003 \001(\t\"\014\n\nGetRequest2\207\001\n\016Coun"
    "terService\022\?\n\tfetch_add\022\030.example.FetchA"
    "ddRequest\032\030.example.CounterResponse\0224\n\003g"
    "et\022\023.example.GetRequest\032\030.example.Counte"
    "rResponseB\003\200\001\001", 334);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "counter.proto", &protobuf_RegisterTypes);
  Snapshot::default_instance_ = new Snapshot();
  FetchAddRequest::default_instance_ = new FetchAddRequest();
  CounterResponse::default_instance_ = new CounterResponse();
  GetRequest::default_instance_ = new GetRequest();
  Snapshot::default_instance_->InitAsDefaultInstance();
  FetchAddRequest::default_instance_->InitAsDefaultInstance();
  CounterResponse::default_instance_->InitAsDefaultInstance();
  GetRequest::default_instance_->InitAsDefaultInstance();
  ::google::protobuf::internal::OnShutdown(&protobuf_ShutdownFile_counter_2eproto);
}

// Force AddDescriptors() to be called at static initialization time.
struct StaticDescriptorInitializer_counter_2eproto {
  StaticDescriptorInitializer_counter_2eproto() {
    protobuf_AddDesc_counter_2eproto();
  }
} static_descriptor_initializer_counter_2eproto_;


// ===================================================================

#ifndef _MSC_VER
const int Snapshot::kValueFieldNumber;
#endif  // !_MSC_VER

Snapshot::Snapshot()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void Snapshot::InitAsDefaultInstance() {
}

Snapshot::Snapshot(const Snapshot& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void Snapshot::SharedCtor() {
  _cached_size_ = 0;
  value_ = GOOGLE_LONGLONG(0);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

Snapshot::~Snapshot() {
  SharedDtor();
}

void Snapshot::SharedDtor() {
  if (this != default_instance_) {
  }
}

void Snapshot::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* Snapshot::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return Snapshot_descriptor_;
}

const Snapshot& Snapshot::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_counter_2eproto();  return *default_instance_;
}

Snapshot* Snapshot::default_instance_ = NULL;

Snapshot* Snapshot::New() const {
  return new Snapshot;
}

void Snapshot::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    value_ = GOOGLE_LONGLONG(0);
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool Snapshot::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required int64 value = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &value_)));
          set_has_value();
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

void Snapshot::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required int64 value = 1;
  if (has_value()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(1, this->value(), output);
  }
  
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* Snapshot::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required int64 value = 1;
  if (has_value()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(1, this->value(), target);
  }
  
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int Snapshot::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required int64 value = 1;
    if (has_value()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int64Size(
          this->value());
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

void Snapshot::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const Snapshot* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const Snapshot*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void Snapshot::MergeFrom(const Snapshot& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_value()) {
      set_value(from.value());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void Snapshot::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Snapshot::CopyFrom(const Snapshot& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Snapshot::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;
  
  return true;
}

void Snapshot::Swap(Snapshot* other) {
  if (other != this) {
    std::swap(value_, other->value_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata Snapshot::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = Snapshot_descriptor_;
  metadata.reflection = Snapshot_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int FetchAddRequest::kValueFieldNumber;
const int FetchAddRequest::kDummyPaddingFieldNumber;
#endif  // !_MSC_VER

FetchAddRequest::FetchAddRequest()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void FetchAddRequest::InitAsDefaultInstance() {
}

FetchAddRequest::FetchAddRequest(const FetchAddRequest& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void FetchAddRequest::SharedCtor() {
  _cached_size_ = 0;
  value_ = GOOGLE_LONGLONG(0);
  dummy_padding_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

FetchAddRequest::~FetchAddRequest() {
  SharedDtor();
}

void FetchAddRequest::SharedDtor() {
  if (dummy_padding_ != &::google::protobuf::internal::kEmptyString) {
    delete dummy_padding_;
  }
  if (this != default_instance_) {
  }
}

void FetchAddRequest::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* FetchAddRequest::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return FetchAddRequest_descriptor_;
}

const FetchAddRequest& FetchAddRequest::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_counter_2eproto();  return *default_instance_;
}

FetchAddRequest* FetchAddRequest::default_instance_ = NULL;

FetchAddRequest* FetchAddRequest::New() const {
  return new FetchAddRequest;
}

void FetchAddRequest::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    value_ = GOOGLE_LONGLONG(0);
    if (has_dummy_padding()) {
      if (dummy_padding_ != &::google::protobuf::internal::kEmptyString) {
        dummy_padding_->clear();
      }
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool FetchAddRequest::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required int64 value = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &value_)));
          set_has_value();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(18)) goto parse_dummy_padding;
        break;
      }
      
      // optional string dummy_padding = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_dummy_padding:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_dummy_padding()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->dummy_padding().data(), this->dummy_padding().length(),
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

void FetchAddRequest::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required int64 value = 1;
  if (has_value()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(1, this->value(), output);
  }
  
  // optional string dummy_padding = 2;
  if (has_dummy_padding()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->dummy_padding().data(), this->dummy_padding().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      2, this->dummy_padding(), output);
  }
  
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* FetchAddRequest::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required int64 value = 1;
  if (has_value()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(1, this->value(), target);
  }
  
  // optional string dummy_padding = 2;
  if (has_dummy_padding()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->dummy_padding().data(), this->dummy_padding().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        2, this->dummy_padding(), target);
  }
  
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int FetchAddRequest::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required int64 value = 1;
    if (has_value()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int64Size(
          this->value());
    }
    
    // optional string dummy_padding = 2;
    if (has_dummy_padding()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->dummy_padding());
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

void FetchAddRequest::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const FetchAddRequest* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const FetchAddRequest*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void FetchAddRequest::MergeFrom(const FetchAddRequest& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_value()) {
      set_value(from.value());
    }
    if (from.has_dummy_padding()) {
      set_dummy_padding(from.dummy_padding());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void FetchAddRequest::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void FetchAddRequest::CopyFrom(const FetchAddRequest& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool FetchAddRequest::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;
  
  return true;
}

void FetchAddRequest::Swap(FetchAddRequest* other) {
  if (other != this) {
    std::swap(value_, other->value_);
    std::swap(dummy_padding_, other->dummy_padding_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata FetchAddRequest::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = FetchAddRequest_descriptor_;
  metadata.reflection = FetchAddRequest_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
const int CounterResponse::kSuccessFieldNumber;
const int CounterResponse::kValueFieldNumber;
const int CounterResponse::kRedirectFieldNumber;
#endif  // !_MSC_VER

CounterResponse::CounterResponse()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void CounterResponse::InitAsDefaultInstance() {
}

CounterResponse::CounterResponse(const CounterResponse& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void CounterResponse::SharedCtor() {
  _cached_size_ = 0;
  success_ = false;
  value_ = GOOGLE_LONGLONG(0);
  redirect_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

CounterResponse::~CounterResponse() {
  SharedDtor();
}

void CounterResponse::SharedDtor() {
  if (redirect_ != &::google::protobuf::internal::kEmptyString) {
    delete redirect_;
  }
  if (this != default_instance_) {
  }
}

void CounterResponse::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* CounterResponse::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return CounterResponse_descriptor_;
}

const CounterResponse& CounterResponse::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_counter_2eproto();  return *default_instance_;
}

CounterResponse* CounterResponse::default_instance_ = NULL;

CounterResponse* CounterResponse::New() const {
  return new CounterResponse;
}

void CounterResponse::Clear() {
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    success_ = false;
    value_ = GOOGLE_LONGLONG(0);
    if (has_redirect()) {
      if (redirect_ != &::google::protobuf::internal::kEmptyString) {
        redirect_->clear();
      }
    }
  }
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool CounterResponse::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // required bool success = 1;
      case 1: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   bool, ::google::protobuf::internal::WireFormatLite::TYPE_BOOL>(
                 input, &success_)));
          set_has_success();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(16)) goto parse_value;
        break;
      }
      
      // optional int64 value = 2;
      case 2: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_VARINT) {
         parse_value:
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::int64, ::google::protobuf::internal::WireFormatLite::TYPE_INT64>(
                 input, &value_)));
          set_has_value();
        } else {
          goto handle_uninterpreted;
        }
        if (input->ExpectTag(26)) goto parse_redirect;
        break;
      }
      
      // optional string redirect = 3;
      case 3: {
        if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
            ::google::protobuf::internal::WireFormatLite::WIRETYPE_LENGTH_DELIMITED) {
         parse_redirect:
          DO_(::google::protobuf::internal::WireFormatLite::ReadString(
                input, this->mutable_redirect()));
          ::google::protobuf::internal::WireFormat::VerifyUTF8String(
            this->redirect().data(), this->redirect().length(),
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

void CounterResponse::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // required bool success = 1;
  if (has_success()) {
    ::google::protobuf::internal::WireFormatLite::WriteBool(1, this->success(), output);
  }
  
  // optional int64 value = 2;
  if (has_value()) {
    ::google::protobuf::internal::WireFormatLite::WriteInt64(2, this->value(), output);
  }
  
  // optional string redirect = 3;
  if (has_redirect()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->redirect().data(), this->redirect().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    ::google::protobuf::internal::WireFormatLite::WriteString(
      3, this->redirect(), output);
  }
  
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* CounterResponse::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  // required bool success = 1;
  if (has_success()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteBoolToArray(1, this->success(), target);
  }
  
  // optional int64 value = 2;
  if (has_value()) {
    target = ::google::protobuf::internal::WireFormatLite::WriteInt64ToArray(2, this->value(), target);
  }
  
  // optional string redirect = 3;
  if (has_redirect()) {
    ::google::protobuf::internal::WireFormat::VerifyUTF8String(
      this->redirect().data(), this->redirect().length(),
      ::google::protobuf::internal::WireFormat::SERIALIZE);
    target =
      ::google::protobuf::internal::WireFormatLite::WriteStringToArray(
        3, this->redirect(), target);
  }
  
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int CounterResponse::ByteSize() const {
  int total_size = 0;
  
  if (_has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    // required bool success = 1;
    if (has_success()) {
      total_size += 1 + 1;
    }
    
    // optional int64 value = 2;
    if (has_value()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::Int64Size(
          this->value());
    }
    
    // optional string redirect = 3;
    if (has_redirect()) {
      total_size += 1 +
        ::google::protobuf::internal::WireFormatLite::StringSize(
          this->redirect());
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

void CounterResponse::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const CounterResponse* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const CounterResponse*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void CounterResponse::MergeFrom(const CounterResponse& from) {
  GOOGLE_CHECK_NE(&from, this);
  if (from._has_bits_[0 / 32] & (0xffu << (0 % 32))) {
    if (from.has_success()) {
      set_success(from.success());
    }
    if (from.has_value()) {
      set_value(from.value());
    }
    if (from.has_redirect()) {
      set_redirect(from.redirect());
    }
  }
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void CounterResponse::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void CounterResponse::CopyFrom(const CounterResponse& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool CounterResponse::IsInitialized() const {
  if ((_has_bits_[0] & 0x00000001) != 0x00000001) return false;
  
  return true;
}

void CounterResponse::Swap(CounterResponse* other) {
  if (other != this) {
    std::swap(success_, other->success_);
    std::swap(value_, other->value_);
    std::swap(redirect_, other->redirect_);
    std::swap(_has_bits_[0], other->_has_bits_[0]);
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata CounterResponse::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = CounterResponse_descriptor_;
  metadata.reflection = CounterResponse_reflection_;
  return metadata;
}


// ===================================================================

#ifndef _MSC_VER
#endif  // !_MSC_VER

GetRequest::GetRequest()
  : ::google::protobuf::Message() {
  SharedCtor();
}

void GetRequest::InitAsDefaultInstance() {
}

GetRequest::GetRequest(const GetRequest& from)
  : ::google::protobuf::Message() {
  SharedCtor();
  MergeFrom(from);
}

void GetRequest::SharedCtor() {
  _cached_size_ = 0;
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
}

GetRequest::~GetRequest() {
  SharedDtor();
}

void GetRequest::SharedDtor() {
  if (this != default_instance_) {
  }
}

void GetRequest::SetCachedSize(int size) const {
  GOOGLE_SAFE_CONCURRENT_WRITES_BEGIN();
  _cached_size_ = size;
  GOOGLE_SAFE_CONCURRENT_WRITES_END();
}
const ::google::protobuf::Descriptor* GetRequest::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return GetRequest_descriptor_;
}

const GetRequest& GetRequest::default_instance() {
  if (default_instance_ == NULL) protobuf_AddDesc_counter_2eproto();  return *default_instance_;
}

GetRequest* GetRequest::default_instance_ = NULL;

GetRequest* GetRequest::New() const {
  return new GetRequest;
}

void GetRequest::Clear() {
  ::memset(_has_bits_, 0, sizeof(_has_bits_));
  mutable_unknown_fields()->Clear();
}

bool GetRequest::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!(EXPRESSION)) return false
  ::google::protobuf::uint32 tag;
  while ((tag = input->ReadTag()) != 0) {
    if (::google::protobuf::internal::WireFormatLite::GetTagWireType(tag) ==
        ::google::protobuf::internal::WireFormatLite::WIRETYPE_END_GROUP) {
      return true;
    }
    DO_(::google::protobuf::internal::WireFormat::SkipField(
          input, tag, mutable_unknown_fields()));
  }
  return true;
#undef DO_
}

void GetRequest::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  if (!unknown_fields().empty()) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        unknown_fields(), output);
  }
}

::google::protobuf::uint8* GetRequest::SerializeWithCachedSizesToArray(
    ::google::protobuf::uint8* target) const {
  if (!unknown_fields().empty()) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        unknown_fields(), target);
  }
  return target;
}

int GetRequest::ByteSize() const {
  int total_size = 0;
  
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

void GetRequest::MergeFrom(const ::google::protobuf::Message& from) {
  GOOGLE_CHECK_NE(&from, this);
  const GetRequest* source =
    ::google::protobuf::internal::dynamic_cast_if_available<const GetRequest*>(
      &from);
  if (source == NULL) {
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
    MergeFrom(*source);
  }
}

void GetRequest::MergeFrom(const GetRequest& from) {
  GOOGLE_CHECK_NE(&from, this);
  mutable_unknown_fields()->MergeFrom(from.unknown_fields());
}

void GetRequest::CopyFrom(const ::google::protobuf::Message& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void GetRequest::CopyFrom(const GetRequest& from) {
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool GetRequest::IsInitialized() const {
  
  return true;
}

void GetRequest::Swap(GetRequest* other) {
  if (other != this) {
    _unknown_fields_.Swap(&other->_unknown_fields_);
    std::swap(_cached_size_, other->_cached_size_);
  }
}

::google::protobuf::Metadata GetRequest::GetMetadata() const {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::Metadata metadata;
  metadata.descriptor = GetRequest_descriptor_;
  metadata.reflection = GetRequest_reflection_;
  return metadata;
}


// ===================================================================

CounterService::~CounterService() {}

const ::google::protobuf::ServiceDescriptor* CounterService::descriptor() {
  protobuf_AssignDescriptorsOnce();
  return CounterService_descriptor_;
}

const ::google::protobuf::ServiceDescriptor* CounterService::GetDescriptor() {
  protobuf_AssignDescriptorsOnce();
  return CounterService_descriptor_;
}

void CounterService::fetch_add(::google::protobuf::RpcController* controller,
                         const ::example::FetchAddRequest*,
                         ::example::CounterResponse*,
                         ::google::protobuf::Closure* done) {
  controller->SetFailed("Method fetch_add() not implemented.");
  done->Run();
}

void CounterService::get(::google::protobuf::RpcController* controller,
                         const ::example::GetRequest*,
                         ::example::CounterResponse*,
                         ::google::protobuf::Closure* done) {
  controller->SetFailed("Method get() not implemented.");
  done->Run();
}

void CounterService::CallMethod(const ::google::protobuf::MethodDescriptor* method,
                             ::google::protobuf::RpcController* controller,
                             const ::google::protobuf::Message* request,
                             ::google::protobuf::Message* response,
                             ::google::protobuf::Closure* done) {
  GOOGLE_DCHECK_EQ(method->service(), CounterService_descriptor_);
  switch(method->index()) {
    case 0:
      fetch_add(controller,
             ::google::protobuf::down_cast<const ::example::FetchAddRequest*>(request),
             ::google::protobuf::down_cast< ::example::CounterResponse*>(response),
             done);
      break;
    case 1:
      get(controller,
             ::google::protobuf::down_cast<const ::example::GetRequest*>(request),
             ::google::protobuf::down_cast< ::example::CounterResponse*>(response),
             done);
      break;
    default:
      GOOGLE_LOG(FATAL) << "Bad method index; this should never happen.";
      break;
  }
}

const ::google::protobuf::Message& CounterService::GetRequestPrototype(
    const ::google::protobuf::MethodDescriptor* method) const {
  GOOGLE_DCHECK_EQ(method->service(), descriptor());
  switch(method->index()) {
    case 0:
      return ::example::FetchAddRequest::default_instance();
    case 1:
      return ::example::GetRequest::default_instance();
    default:
      GOOGLE_LOG(FATAL) << "Bad method index; this should never happen.";
      return *reinterpret_cast< ::google::protobuf::Message*>(NULL);
  }
}

const ::google::protobuf::Message& CounterService::GetResponsePrototype(
    const ::google::protobuf::MethodDescriptor* method) const {
  GOOGLE_DCHECK_EQ(method->service(), descriptor());
  switch(method->index()) {
    case 0:
      return ::example::CounterResponse::default_instance();
    case 1:
      return ::example::CounterResponse::default_instance();
    default:
      GOOGLE_LOG(FATAL) << "Bad method index; this should never happen.";
      return *reinterpret_cast< ::google::protobuf::Message*>(NULL);
  }
}

CounterService_Stub::CounterService_Stub(::google::protobuf::RpcChannel* channel)
  : channel_(channel), owns_channel_(false) {}
CounterService_Stub::CounterService_Stub(
    ::google::protobuf::RpcChannel* channel,
    ::google::protobuf::Service::ChannelOwnership ownership)
  : channel_(channel),
    owns_channel_(ownership == ::google::protobuf::Service::STUB_OWNS_CHANNEL) {}
CounterService_Stub::~CounterService_Stub() {
  if (owns_channel_) delete channel_;
}

void CounterService_Stub::fetch_add(::google::protobuf::RpcController* controller,
                              const ::example::FetchAddRequest* request,
                              ::example::CounterResponse* response,
                              ::google::protobuf::Closure* done) {
  channel_->CallMethod(descriptor()->method(0),
                       controller, request, response, done);
}
void CounterService_Stub::get(::google::protobuf::RpcController* controller,
                              const ::example::GetRequest* request,
                              ::example::CounterResponse* response,
                              ::google::protobuf::Closure* done) {
  channel_->CallMethod(descriptor()->method(1),
                       controller, request, response, done);
}

// @@protoc_insertion_point(namespace_scope)

}  // namespace example

// @@protoc_insertion_point(global_scope)
