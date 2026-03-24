#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <React/RCTBridgeModule.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

using TssHandle = uint64_t;
using TssStatus = int32_t;

struct TssBuffer {
  uint8_t *data;
  size_t len;
};

struct TssSlice {
  const uint8_t *data;
  size_t len;
};

constexpr TssStatus TSS_OK = 0;
constexpr TssStatus TSS_ERR_ABORT = 10;
constexpr TssStatus TSS_ERR_ABORT_BAN = 11;

extern "C" {
const char *tss_last_error(void);
size_t tss_last_error_len(void);
size_t tss_abort_culprit_count(void);
uint16_t tss_abort_culprit(size_t index);
uint16_t tss_abort_banned_party(void);
TssStatus tss_init(uint32_t flags);
void tss_buffer_free(TssBuffer *buf);
void tss_handle_free(TssHandle handle);
TssStatus tss_handle_identifier(TssHandle handle, uint16_t *out_id);
TssStatus tss_handle_verifying_share(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_group_key(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_pubkey_package(TssHandle handle, TssBuffer *out);
uint8_t tss_handle_ciphersuite(TssHandle handle);
TssStatus tss_handle_export(TssHandle handle, TssBuffer *out);
TssStatus tss_handle_import(const uint8_t *data, size_t data_len, uint8_t suite, TssHandle *out_handle);
TssStatus tss_dkg_new(
    uint8_t suite,
    uint16_t self_id,
    uint16_t max_signers,
    uint16_t min_signers,
    const uint8_t *session_id,
    size_t session_id_len,
    TssHandle *out_session,
    TssBuffer *out_messages);
TssStatus tss_dkg_next(
    TssHandle session,
    TssSlice messages,
    TssHandle *out_key_share,
    TssBuffer *out_pubkey_package,
    TssBuffer *out_messages,
    bool *out_complete);
TssStatus tss_sign_new(
    TssHandle key_share,
    TssSlice message,
    const uint16_t *counterparties,
    size_t counterparties_len,
    const uint8_t *sign_id,
    size_t sign_id_len,
    TssHandle *out_session,
    TssBuffer *out_messages);
TssStatus tss_sign_next(
    TssHandle session,
    TssSlice messages,
    TssBuffer *out_signature,
    TssBuffer *out_messages,
    bool *out_complete);
TssStatus tss_refresh_new(
    TssHandle key_share,
    const uint16_t *participants,
    size_t participants_len,
    TssHandle *out_session,
    TssBuffer *out_messages);
TssStatus tss_refresh_receiver(TssHandle key_share, TssHandle *out_session);
TssStatus tss_refresh_next(
    TssHandle session,
    TssSlice messages,
    TssHandle *out_key_share,
    TssBuffer *out_pubkey_package,
    TssBuffer *out_messages,
    bool *out_complete);
void tss_session_free(TssHandle session);
const char *tss_version(void);
bool tss_verify(uint8_t suite,
                struct TssSlice message,
                struct TssSlice signature,
                struct TssSlice public_key);
}

NSString *LastErrorMessage() {
  const char *message = tss_last_error();
  if (message == nullptr) {
    return @"libtss native call failed";
  }

  size_t len = tss_last_error_len();
  if (len == 0) {
    return [NSString stringWithUTF8String:message] ?: @"libtss native call failed";
  }

  return [[NSString alloc] initWithBytes:message length:len encoding:NSUTF8StringEncoding]
      ?: @"libtss native call failed";
}

NSError *BridgeError(NSString *message) {
  return [NSError errorWithDomain:@"libtss"
                             code:-1
                         userInfo:@{NSLocalizedDescriptionKey : message}];
}

NSArray<NSNumber *> *AbortCulprits() {
  NSMutableArray<NSNumber *> *culprits = [NSMutableArray array];
  size_t culpritCount = tss_abort_culprit_count();
  for (size_t index = 0; index < culpritCount; ++index) {
    [culprits addObject:@(tss_abort_culprit(index))];
  }
  return culprits;
}

NSError *StatusError(TssStatus status) {
  NSString *message = LastErrorMessage();
  NSMutableDictionary *userInfo = [NSMutableDictionary dictionaryWithObject:message
                                                                     forKey:NSLocalizedDescriptionKey];
  userInfo[@"code"] = @(status);

  if (status == TSS_ERR_ABORT || status == TSS_ERR_ABORT_BAN) {
    NSArray<NSNumber *> *culprits = AbortCulprits();
    if (culprits.count > 0) {
      userInfo[@"culprits"] = culprits;
    }
  }

  if (status == TSS_ERR_ABORT_BAN) {
    uint16_t bannedParty = tss_abort_banned_party();
    if (bannedParty != 0) {
      userInfo[@"bannedParty"] = @(bannedParty);
    }
  }

  return [NSError errorWithDomain:@"libtss" code:status userInfo:userInfo];
}

void RejectStatus(RCTPromiseRejectBlock reject, TssStatus status) {
  NSError *error = StatusError(status);
  reject(@"E_LIBTSS", error.localizedDescription, error);
}

void RejectBridgeError(RCTPromiseRejectBlock reject, NSString *message) {
  NSError *error = BridgeError(message);
  reject(@"E_LIBTSS", message, error);
}

BOOL ParseHandle(NSString *handle, TssHandle *outHandle, RCTPromiseRejectBlock reject) {
  if (handle == nil) {
    RejectBridgeError(reject, @"handle is required");
    return NO;
  }

  errno = 0;
  const char *raw = handle.UTF8String;
  char *end = nullptr;
  unsigned long long parsed = std::strtoull(raw, &end, 10);
  if (errno != 0 || end == raw || end == nullptr || *end != '\0') {
    RejectBridgeError(reject, @"invalid handle");
    return NO;
  }

  *outHandle = static_cast<TssHandle>(parsed);
  return YES;
}

NSData *DecodeBase64(NSString *value, RCTPromiseRejectBlock reject) {
  if (value == nil) {
    RejectBridgeError(reject, @"base64 input is required");
    return nil;
  }

  NSData *decoded = [[NSData alloc] initWithBase64EncodedString:value options:0];
  if (decoded == nil && value.length > 0) {
    RejectBridgeError(reject, @"invalid base64 input");
    return nil;
  }

  return decoded ?: [NSData data];
}

TssSlice MakeSlice(NSData *data) {
  return TssSlice{static_cast<const uint8_t *>(data.bytes), static_cast<size_t>(data.length)};
}

NSString *TakeBase64(TssBuffer &buffer) {
  NSData *data = [NSData dataWithBytes:buffer.data length:buffer.len];
  tss_buffer_free(&buffer);
  return [data base64EncodedStringWithOptions:0];
}

void ReleaseBuffer(TssBuffer &buffer) {
  if (buffer.data != nullptr || buffer.len != 0) {
    tss_buffer_free(&buffer);
  }
}

NSString *HandleString(TssHandle handle) {
  return [NSString stringWithFormat:@"%llu", static_cast<unsigned long long>(handle)];
}

NSDictionary *SessionInitResult(TssHandle handle, NSString *messages) {
  return @{@"handle" : HandleString(handle), @"messages" : messages};
}

NSDictionary *RoundResult(
    BOOL complete,
    NSString *messages,
    NSString *keyShareHandle,
    NSString *pubkeyPackage,
    NSString *signature) {
  NSMutableDictionary *result = [NSMutableDictionary dictionaryWithObject:@(complete) forKey:@"complete"];
  if (messages != nil) {
    result[@"messages"] = messages;
  }
  if (keyShareHandle != nil) {
    result[@"keyShareHandle"] = keyShareHandle;
  }
  if (pubkeyPackage != nil) {
    result[@"pubkeyPackage"] = pubkeyPackage;
  }
  if (signature != nil) {
    result[@"signature"] = signature;
  }
  return result;
}

}  // namespace

@interface Libtss : NSObject <RCTBridgeModule>
@end

@implementation Libtss

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(dkgNew:(nonnull NSNumber *)suite
                  selfId:(nonnull NSNumber *)selfId
                  maxSigners:(nonnull NSNumber *)maxSigners
                  minSigners:(nonnull NSNumber *)minSigners
                  sessionId:(NSString * _Nullable)sessionId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  NSData *sessionData = nil;
  if (sessionId != nil) {
    sessionData = DecodeBase64(sessionId, reject);
    if (sessionData == nil) {
      return;
    }
  }

  TssHandle session = 0;
  TssBuffer messages{nullptr, 0};
  TssStatus status = tss_dkg_new(
      suite.unsignedCharValue,
      selfId.unsignedShortValue,
      maxSigners.unsignedShortValue,
      minSigners.unsignedShortValue,
      sessionData == nil ? nullptr : static_cast<const uint8_t *>(sessionData.bytes),
      sessionData == nil ? 0 : static_cast<size_t>(sessionData.length),
      &session,
      &messages);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(SessionInitResult(session, TakeBase64(messages)));
}

RCT_EXPORT_METHOD(dkgNext:(NSString *)handle
                  messages:(NSString *)messages
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle session = 0;
  if (!ParseHandle(handle, &session, reject)) {
    return;
  }

  NSData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }

  TssHandle keyShare = 0;
  TssBuffer pubkeyPackage{nullptr, 0};
  TssBuffer outMessages{nullptr, 0};
  bool complete = false;
  TssStatus status = tss_dkg_next(
      session,
      MakeSlice(messageData),
      &keyShare,
      &pubkeyPackage,
      &outMessages,
      &complete);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  if (complete) {
    ReleaseBuffer(outMessages);
    resolve(RoundResult(YES, nil, HandleString(keyShare), TakeBase64(pubkeyPackage), nil));
    return;
  }

  ReleaseBuffer(pubkeyPackage);
  resolve(RoundResult(NO, TakeBase64(outMessages), nil, nil, nil));
}

RCT_EXPORT_METHOD(signNew:(NSString *)keyShareHandle
                  message:(NSString *)message
                  counterparties:(NSArray<NSNumber *> * _Nullable)counterparties
                  signId:(NSString * _Nullable)signId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }

  NSData *messageData = DecodeBase64(message, reject);
  if (messageData == nil) {
    return;
  }

  std::vector<uint16_t> cpVec;
  const uint16_t *cpPtr = nullptr;
  size_t cpLen = 0;
  if (counterparties != nil && counterparties.count > 0) {
    cpVec.reserve(counterparties.count);
    for (NSNumber *n in counterparties) {
      cpVec.push_back(n.unsignedShortValue);
    }
    cpPtr = cpVec.data();
    cpLen = cpVec.size();
  }

  NSData *signIdData = nil;
  const uint8_t *signIdPtr = nullptr;
  size_t signIdLen = 0;
  if (signId != nil) {
    signIdData = DecodeBase64(signId, reject);
    if (signIdData == nil) {
      return;
    }
    signIdPtr = static_cast<const uint8_t *>(signIdData.bytes);
    signIdLen = static_cast<size_t>(signIdData.length);
  }

  TssHandle session = 0;
  TssBuffer outMessages{nullptr, 0};
  TssStatus status = tss_sign_new(
      keyShare,
      MakeSlice(messageData),
      cpPtr,
      cpLen,
      signIdPtr,
      signIdLen,
      &session,
      &outMessages);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(SessionInitResult(session, TakeBase64(outMessages)));
}

RCT_EXPORT_METHOD(signNext:(NSString *)handle
                  messages:(NSString *)messages
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle session = 0;
  if (!ParseHandle(handle, &session, reject)) {
    return;
  }

  NSData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }

  TssBuffer signature{nullptr, 0};
  TssBuffer outMessages{nullptr, 0};
  bool complete = false;
  TssStatus status = tss_sign_next(session, MakeSlice(messageData), &signature, &outMessages, &complete);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  if (complete) {
    ReleaseBuffer(outMessages);
    resolve(RoundResult(YES, nil, nil, nil, TakeBase64(signature)));
    return;
  }

  ReleaseBuffer(signature);
  resolve(RoundResult(NO, TakeBase64(outMessages), nil, nil, nil));
}

RCT_EXPORT_METHOD(refreshNew:(NSString *)keyShareHandle
                  participants:(NSArray<NSNumber *> * _Nullable)participants
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }

  std::vector<uint16_t> pVec;
  const uint16_t *pPtr = nullptr;
  size_t pLen = 0;
  if (participants != nil && participants.count > 0) {
    pVec.reserve(participants.count);
    for (NSNumber *n in participants) {
      pVec.push_back(n.unsignedShortValue);
    }
    pPtr = pVec.data();
    pLen = pVec.size();
  }

  TssHandle session = 0;
  TssBuffer messages{nullptr, 0};
  TssStatus status = tss_refresh_new(keyShare, pPtr, pLen, &session, &messages);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(SessionInitResult(session, TakeBase64(messages)));
}

RCT_EXPORT_METHOD(refreshReceiver:(NSString *)keyShareHandle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }

  TssHandle session = 0;
  TssStatus status = tss_refresh_receiver(keyShare, &session);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(session));
}

RCT_EXPORT_METHOD(refreshNext:(NSString *)handle
                  messages:(NSString *)messages
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle session = 0;
  if (!ParseHandle(handle, &session, reject)) {
    return;
  }

  NSData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }

  TssHandle keyShare = 0;
  TssBuffer pubkeyPackage{nullptr, 0};
  TssBuffer outMessages{nullptr, 0};
  bool complete = false;
  TssStatus status = tss_refresh_next(
      session,
      MakeSlice(messageData),
      &keyShare,
      &pubkeyPackage,
      &outMessages,
      &complete);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  if (complete) {
    ReleaseBuffer(outMessages);
    resolve(RoundResult(YES, nil, HandleString(keyShare), TakeBase64(pubkeyPackage), nil));
    return;
  }

  ReleaseBuffer(pubkeyPackage);
  resolve(RoundResult(NO, TakeBase64(outMessages), nil, nil, nil));
}

RCT_EXPORT_METHOD(handleFree:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  tss_handle_free(parsed);
  resolve(nil);
}

RCT_EXPORT_METHOD(handleIdentifier:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  uint16_t identifier = 0;
  TssStatus status = tss_handle_identifier(parsed, &identifier);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(@(identifier));
}

RCT_EXPORT_METHOD(handleVerifyingShare:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_verifying_share(parsed, &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(handleGroupKey:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_group_key(parsed, &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(handlePubkeyPackage:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_pubkey_package(parsed, &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(handleCiphersuite:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  resolve(@(tss_handle_ciphersuite(parsed)));
}

RCT_EXPORT_METHOD(exportKeyShare:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_export(parsed, &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(importKeyShare:(nonnull NSNumber *)suite
                  data:(NSString *)data
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  NSData *decoded = DecodeBase64(data, reject);
  if (decoded == nil) {
    return;
  }

  TssHandle out = 0;
  TssStatus status = tss_handle_import(
      static_cast<const uint8_t *>(decoded.bytes),
      static_cast<size_t>(decoded.length),
      suite.unsignedCharValue,
      &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

RCT_EXPORT_METHOD(version:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  const char *version = tss_version();
  if (version == nullptr) {
    RejectBridgeError(reject, @"missing libtss version");
    return;
  }

  resolve([NSString stringWithUTF8String:version]);
}


RCT_REMAP_METHOD(verify,
                 suite:(NSNumber *)suite
                 message:(NSString *)message
                 signature:(NSString *)signature
                 publicKey:(NSString *)publicKey
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)
{
    NSData *msgData = DecodeBase64(message, reject);
    if (msgData == nil) { return; }
    NSData *sigData = DecodeBase64(signature, reject);
    if (sigData == nil) { return; }
    NSData *pkData = DecodeBase64(publicKey, reject);
    if (pkData == nil) { return; }

    TssSlice msgSlice = { .data = (const uint8_t *)msgData.bytes, .len = msgData.length };
    TssSlice sigSlice = { .data = (const uint8_t *)sigData.bytes, .len = sigData.length };
    TssSlice pkSlice = { .data = (const uint8_t *)pkData.bytes, .len = pkData.length };

    bool result = tss_verify([suite unsignedCharValue], msgSlice, sigSlice, pkSlice);
    resolve(@(result));
}

RCT_EXPORT_METHOD(initialize:(NSDictionary *)options
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  BOOL mlock = [options[@"mlock"] boolValue];
  uint32_t flags = mlock ? 1 : 0;
  TssStatus status = tss_init(flags);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(nil);
}

static NSString *const kKeychainService = @"com.libtss.keyshare";

RCT_EXPORT_METHOD(exportKeyShareSecure:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_export(parsed, &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  NSData *wrappedData = [NSData dataWithBytesNoCopy:out.data
                                             length:out.len
                                       freeWhenDone:NO];

  NSString *uuid = [[NSUUID UUID] UUIDString];
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : kKeychainService,
    (__bridge id)kSecAttrAccount : uuid,
    (__bridge id)kSecValueData : wrappedData,
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  };
  OSStatus ks = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
  tss_buffer_free(&out);

  if (ks != errSecSuccess) {
    RejectBridgeError(reject, [NSString stringWithFormat:@"Keychain SecItemAdd failed: %d", (int)ks]);
    return;
  }

  resolve(uuid);
}

RCT_EXPORT_METHOD(importKeyShareSecure:(nonnull NSNumber *)suite
                  keychainId:(NSString *)keychainId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : kKeychainService,
    (__bridge id)kSecAttrAccount : keychainId,
    (__bridge id)kSecReturnData : @YES,
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
  };
  CFTypeRef result = NULL;
  OSStatus ks = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
  if (ks != errSecSuccess || result == NULL) {
    RejectBridgeError(reject, [NSString stringWithFormat:@"Keychain SecItemCopyMatching failed: %d", (int)ks]);
    return;
  }

  NSData *keychainData = (__bridge_transfer NSData *)result;

  // Copy into a mutable buffer we own so we can safely wipe after import.
  // SecItemCopyMatching returns an immutable NSData whose backing memory may
  // not be safely writable (memset on it is technically UB). The mutable copy
  // is guaranteed heap-writable. The original NSData is released by ARC.
  NSMutableData *mutableCopy = [keychainData mutableCopy];
  keychainData = nil;  // release immutable copy early

  double suiteDouble = suite.doubleValue;
  int suiteValue = (int)suiteDouble;
  if (suiteDouble != (double)suiteValue || suiteValue < 0 || suiteValue > 255) {
    RejectBridgeError(reject, @"invalid ciphersuite value");
    memset_s(mutableCopy.mutableBytes, mutableCopy.length, 0, mutableCopy.length);
    return;
  }

  TssHandle out = 0;
  TssStatus status = tss_handle_import(
      static_cast<const uint8_t *>(mutableCopy.bytes),
      static_cast<size_t>(mutableCopy.length),
      static_cast<uint8_t>(suiteValue),
      &out);

  memset_s(mutableCopy.mutableBytes, mutableCopy.length, 0, mutableCopy.length);

  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

@end
