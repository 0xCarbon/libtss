#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <React/RCTBridgeModule.h>

#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

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
constexpr TssStatus TSS_ERR_INVALID_CONFIG = 1;
constexpr TssStatus TSS_ERR_HANDLE_INVALID = 7;
constexpr TssStatus TSS_ERR_INTERNAL_PANIC = 255;
constexpr TssStatus TSS_ERR_ABORT = 10;
constexpr TssStatus TSS_ERR_ABORT_BAN = 11;
constexpr uint8_t TSS_NO_RECOVERY_ID = 255;

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
TssStatus tss_handle_chain_code(TssHandle handle, TssBuffer *out);
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
TssStatus tss_sign_next_recoverable(
    TssHandle session,
    TssSlice messages,
    TssBuffer *out_signature,
    uint8_t *out_recovery_id,
    TssBuffer *out_messages,
    bool *out_complete);
TssStatus tss_refresh_new(
    TssHandle key_share,
    const uint16_t *participants,
    size_t participants_len,
    TssHandle *out_session,
    TssBuffer *out_messages);
TssStatus tss_refresh_receiver(TssHandle key_share, uint16_t dealer, TssHandle *out_session);
TssStatus tss_refresh_new_dkls(TssHandle key_share,
                               const uint8_t *session_id,
                               size_t session_id_len,
                               TssHandle *out_session,
                               TssBuffer *out_messages);
TssStatus tss_repair_helper_term(TssHandle key_share,
                                 const uint16_t *helpers,
                                 size_t helpers_len,
                                 uint16_t target,
                                 TssSlice repair_id,
                                 TssBuffer *out_messages);
TssStatus tss_repair_assemble(uint8_t suite,
                              TssSlice pubkey_package,
                              uint16_t target,
                              TssSlice messages,
                              TssHandle *out_handle);
TssStatus tss_bolt3_derive(TssHandle key_share, TssSlice per_commitment_point, TssHandle *out_handle);
TssStatus tss_bolt3_derive_revocation(TssHandle key_share,
                                      TssSlice per_commitment_point,
                                      TssSlice per_commitment_secret,
                                      TssHandle *out_handle);
TssStatus tss_bolt3_derive_pubkey_package(TssSlice pubkey_package,
                                          TssSlice per_commitment_point,
                                          TssBuffer *out_pubkey_package);
TssStatus tss_bolt3_derive_revocation_pubkey_package(TssSlice pubkey_package,
                                                     TssSlice per_commitment_point,
                                                     TssBuffer *out_pubkey_package);
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

// Errors detected in the bridge itself carry a status code like native
// errors, so JS sees a regular TssError code instead of INTERNAL_PANIC.
NSError *BridgeError(NSString *message, TssStatus code) {
  return [NSError errorWithDomain:@"libtss"
                             code:code
                         userInfo:@{NSLocalizedDescriptionKey : message, @"code" : @(code)}];
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

void RejectBridgeError(RCTPromiseRejectBlock reject, NSString *message,
                       TssStatus code = TSS_ERR_INVALID_CONFIG) {
  NSError *error = BridgeError(message, code);
  reject(@"E_LIBTSS", message, error);
}

BOOL ParseHandle(NSString *handle, TssHandle *outHandle, RCTPromiseRejectBlock reject) {
  if (handle == nil) {
    RejectBridgeError(reject, @"handle is required", TSS_ERR_HANDLE_INVALID);
    return NO;
  }

  errno = 0;
  const char *raw = handle.UTF8String;
  char *end = nullptr;
  unsigned long long parsed = std::strtoull(raw, &end, 10);
  if (errno != 0 || end == raw || end == nullptr || *end != '\0') {
    RejectBridgeError(reject, @"invalid handle", TSS_ERR_HANDLE_INVALID);
    return NO;
  }

  *outHandle = static_cast<TssHandle>(parsed);
  return YES;
}

void WipeData(NSMutableData *data) {
  if (data != nil && data.length > 0) {
    memset_s(data.mutableBytes, data.length, 0, data.length);
  }
}

// Zeroes the decoded bytes when the enclosing scope exits. Every payload
// decoded from the bridge (protocol messages, key shares, repair terms,
// BOLT 3 secrets) is held in one of these.
struct WipeOnExit {
  NSMutableData *data;
  ~WipeOnExit() { WipeData(data); }
};

int Base64Value(unichar c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// Decodes standard padded base64 straight into a mutable buffer so the only
// plaintext copy is one the caller can wipe.
NSMutableData *DecodeBase64(NSString *value, RCTPromiseRejectBlock reject) {
  if (value == nil) {
    RejectBridgeError(reject, @"base64 input is required");
    return nil;
  }

  NSUInteger length = value.length;
  if (length % 4 != 0) {
    RejectBridgeError(reject, @"invalid base64 input");
    return nil;
  }
  NSUInteger padding = 0;
  if (length > 0 && [value characterAtIndex:length - 1] == '=') padding++;
  if (length > 1 && [value characterAtIndex:length - 2] == '=') padding++;

  NSMutableData *out = [NSMutableData dataWithLength:length / 4 * 3 - padding];
  uint8_t *bytes = static_cast<uint8_t *>(out.mutableBytes);
  NSUInteger written = 0;
  for (NSUInteger i = 0; i < length; i += 4) {
    uint32_t quad = 0;
    for (NSUInteger j = 0; j < 4; ++j) {
      unichar c = [value characterAtIndex:i + j];
      int v;
      if (c == '=' && i + j >= length - padding) {
        v = 0;
      } else {
        v = Base64Value(c);
      }
      if (v < 0) {
        WipeData(out);
        RejectBridgeError(reject, @"invalid base64 input");
        return nil;
      }
      quad = (quad << 6) | static_cast<uint32_t>(v);
    }
    uint8_t chunk[3] = {static_cast<uint8_t>(quad >> 16), static_cast<uint8_t>(quad >> 8),
                        static_cast<uint8_t>(quad)};
    for (int k = 0; k < 3 && written < out.length; ++k) {
      bytes[written++] = chunk[k];
    }
    memset_s(chunk, sizeof chunk, 0, sizeof chunk);
    quad = 0;
  }
  return out;
}

TssSlice MakeSlice(NSData *data) {
  return TssSlice{static_cast<const uint8_t *>(data.bytes), static_cast<size_t>(data.length)};
}

// Encodes the native buffer without an intermediate NSData copy, then frees
// (and thereby zeroes) it.
NSString *TakeBase64(TssBuffer &buffer) {
  NSData *view = [NSData dataWithBytesNoCopy:buffer.data length:buffer.len freeWhenDone:NO];
  NSString *encoded = [view base64EncodedStringWithOptions:0];
  view = nil;
  tss_buffer_free(&buffer);
  return encoded;
}

// Reads an integer argument, rejecting fractional and out-of-range values
// instead of letting NSNumber accessors truncate them.
BOOL CheckedInteger(NSNumber *number, long min, long max, NSString *name, long *out, RCTPromiseRejectBlock reject) {
  double value = number == nil ? NAN : number.doubleValue;
  if (!(value >= static_cast<double>(min) && value <= static_cast<double>(max)) ||
      value != static_cast<double>(static_cast<long>(value))) {
    RejectBridgeError(reject, [NSString stringWithFormat:@"%@ must be an integer in [%ld, %ld]", name, min, max]);
    return NO;
  }
  *out = static_cast<long>(value);
  return YES;
}

BOOL CheckedSuite(NSNumber *number, uint8_t *out, RCTPromiseRejectBlock reject) {
  long value = 0;
  if (!CheckedInteger(number, 0, 0xFF, @"suite", &value, reject)) {
    return NO;
  }
  *out = static_cast<uint8_t>(value);
  return YES;
}

BOOL CheckedIdentifiers(NSArray<NSNumber *> *values, NSString *name, std::vector<uint16_t> *out,
                        RCTPromiseRejectBlock reject) {
  out->clear();
  out->reserve(values.count);
  for (id item in values) {
    if (![item isKindOfClass:[NSNumber class]]) {
      RejectBridgeError(reject, [NSString stringWithFormat:@"%@ must be a number", name]);
      return NO;
    }
    long value = 0;
    if (!CheckedInteger(item, 1, 0xFFFF, name, &value, reject)) {
      return NO;
    }
    out->push_back(static_cast<uint16_t>(value));
  }
  return YES;
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
    NSString *signature,
    NSNumber *recoveryId = nil) {
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
  if (recoveryId != nil) {
    result[@"recoveryId"] = recoveryId;
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
  uint8_t suiteValue = 0;
  long selfValue = 0;
  long maxValue = 0;
  long minValue = 0;
  if (!CheckedSuite(suite, &suiteValue, reject) ||
      !CheckedInteger(selfId, 1, 0xFFFF, @"selfId", &selfValue, reject) ||
      !CheckedInteger(maxSigners, 1, 0xFFFF, @"maxSigners", &maxValue, reject) ||
      !CheckedInteger(minSigners, 1, 0xFFFF, @"minSigners", &minValue, reject)) {
    return;
  }

  NSMutableData *sessionData = nil;
  if (sessionId != nil) {
    sessionData = DecodeBase64(sessionId, reject);
    if (sessionData == nil) {
      return;
    }
  }

  TssHandle session = 0;
  TssBuffer messages{nullptr, 0};
  TssStatus status = tss_dkg_new(
      suiteValue,
      static_cast<uint16_t>(selfValue),
      static_cast<uint16_t>(maxValue),
      static_cast<uint16_t>(minValue),
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

  NSMutableData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }
  WipeOnExit messageGuard{messageData};

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

  std::vector<uint16_t> cpVec;
  const uint16_t *cpPtr = nullptr;
  size_t cpLen = 0;
  if (counterparties != nil && counterparties.count > 0) {
    if (!CheckedIdentifiers(counterparties, @"counterparty", &cpVec, reject)) {
      return;
    }
    cpPtr = cpVec.data();
    cpLen = cpVec.size();
  }

  NSMutableData *messageData = DecodeBase64(message, reject);
  if (messageData == nil) {
    return;
  }
  WipeOnExit messageGuard{messageData};

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

  NSMutableData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }
  WipeOnExit messageGuard{messageData};

  TssBuffer signature{nullptr, 0};
  uint8_t recoveryId = TSS_NO_RECOVERY_ID;
  TssBuffer outMessages{nullptr, 0};
  bool complete = false;
  TssStatus status = tss_sign_next_recoverable(
      session, MakeSlice(messageData), &signature, &recoveryId, &outMessages, &complete);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  if (complete) {
    ReleaseBuffer(outMessages);
    NSNumber *recovery = recoveryId == TSS_NO_RECOVERY_ID ? nil : @(recoveryId);
    resolve(RoundResult(YES, nil, nil, nil, TakeBase64(signature), recovery));
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
    if (!CheckedIdentifiers(participants, @"participant", &pVec, reject)) {
      return;
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

RCT_EXPORT_METHOD(refreshNewDkls:(NSString *)keyShareHandle
                  sessionId:(NSString *)sessionId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }
  NSData *sid = DecodeBase64(sessionId, reject);
  if (sid == nil) {
    return;
  }

  TssHandle session = 0;
  TssBuffer messages{nullptr, 0};
  TssStatus status = tss_refresh_new_dkls(
      keyShare,
      sid.length > 0 ? static_cast<const uint8_t *>(sid.bytes) : nullptr,
      static_cast<size_t>(sid.length),
      &session,
      &messages);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(SessionInitResult(session, TakeBase64(messages)));
}

RCT_EXPORT_METHOD(repairHelperTerm:(NSString *)keyShareHandle
                  helpers:(NSArray<NSNumber *> *)helpers
                  target:(nonnull NSNumber *)target
                  repairId:(NSString *)repairId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }
  if (helpers == nil) {
    RejectBridgeError(reject, @"helpers is required");
    return;
  }
  std::vector<uint16_t> ids;
  long targetValue = 0;
  if (!CheckedIdentifiers(helpers, @"helper", &ids, reject) ||
      !CheckedInteger(target, 1, 0xFFFF, @"target", &targetValue, reject)) {
    return;
  }
  NSData *idData = DecodeBase64(repairId, reject);
  if (idData == nil) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_repair_helper_term(
      keyShare, ids.data(), ids.size(), static_cast<uint16_t>(targetValue), MakeSlice(idData), &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(repairAssemble:(nonnull NSNumber *)suite
                  pubkeyPackage:(NSString *)pubkeyPackage
                  target:(nonnull NSNumber *)target
                  messages:(NSString *)messages
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  uint8_t suiteValue = 0;
  long targetValue = 0;
  if (!CheckedSuite(suite, &suiteValue, reject) ||
      !CheckedInteger(target, 1, 0xFFFF, @"target", &targetValue, reject)) {
    return;
  }
  NSData *package = DecodeBase64(pubkeyPackage, reject);
  if (package == nil) {
    return;
  }
  NSMutableData *blob = DecodeBase64(messages, reject);
  if (blob == nil) {
    return;
  }
  WipeOnExit blobGuard{blob};

  TssHandle out = 0;
  TssStatus status = tss_repair_assemble(
      suiteValue, MakeSlice(package), static_cast<uint16_t>(targetValue), MakeSlice(blob), &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

RCT_EXPORT_METHOD(bolt3Derive:(NSString *)keyShareHandle
                  perCommitmentPoint:(NSString *)perCommitmentPoint
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }
  NSData *point = DecodeBase64(perCommitmentPoint, reject);
  if (point == nil) {
    return;
  }

  TssHandle out = 0;
  TssStatus status = tss_bolt3_derive(keyShare, MakeSlice(point), &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

RCT_EXPORT_METHOD(bolt3DeriveRevocation:(NSString *)keyShareHandle
                  perCommitmentPoint:(NSString *)perCommitmentPoint
                  perCommitmentSecret:(NSString *)perCommitmentSecret
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject)) {
    return;
  }
  NSData *point = DecodeBase64(perCommitmentPoint, reject);
  if (point == nil) {
    return;
  }
  NSMutableData *secret = DecodeBase64(perCommitmentSecret, reject);
  if (secret == nil) {
    return;
  }

  TssHandle out = 0;
  TssStatus status = tss_bolt3_derive_revocation(keyShare, MakeSlice(point), MakeSlice(secret), &out);
  WipeData(secret);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

RCT_EXPORT_METHOD(bolt3DerivePubkeyPackage:(NSString *)pubkeyPackage
                  perCommitmentPoint:(NSString *)perCommitmentPoint
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  NSData *package = DecodeBase64(pubkeyPackage, reject);
  if (package == nil) {
    return;
  }
  NSData *point = DecodeBase64(perCommitmentPoint, reject);
  if (point == nil) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_bolt3_derive_pubkey_package(MakeSlice(package), MakeSlice(point), &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(bolt3DeriveRevocationPubkeyPackage:(NSString *)pubkeyPackage
                  perCommitmentPoint:(NSString *)perCommitmentPoint
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  NSData *package = DecodeBase64(pubkeyPackage, reject);
  if (package == nil) {
    return;
  }
  NSData *point = DecodeBase64(perCommitmentPoint, reject);
  if (point == nil) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_bolt3_derive_revocation_pubkey_package(MakeSlice(package), MakeSlice(point), &out);
  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(TakeBase64(out));
}

RCT_EXPORT_METHOD(refreshReceiver:(NSString *)keyShareHandle
                  dealer:(nonnull NSNumber *)dealer
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle keyShare = 0;
  long dealerValue = 0;
  if (!ParseHandle(keyShareHandle, &keyShare, reject) ||
      !CheckedInteger(dealer, 1, 0xFFFF, @"dealer", &dealerValue, reject)) {
    return;
  }

  TssHandle session = 0;
  TssStatus status = tss_refresh_receiver(keyShare, (uint16_t)dealerValue, &session);
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

  NSMutableData *messageData = DecodeBase64(messages, reject);
  if (messageData == nil) {
    return;
  }
  WipeOnExit messageGuard{messageData};

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

RCT_EXPORT_METHOD(sessionFree:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  tss_session_free(parsed);
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

RCT_EXPORT_METHOD(handleChainCode:(NSString *)handle
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  TssHandle parsed = 0;
  if (!ParseHandle(handle, &parsed, reject)) {
    return;
  }

  TssBuffer out{nullptr, 0};
  TssStatus status = tss_handle_chain_code(parsed, &out);
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
  uint8_t suiteValue = 0;
  if (!CheckedSuite(suite, &suiteValue, reject)) {
    return;
  }
  NSMutableData *decoded = DecodeBase64(data, reject);
  if (decoded == nil) {
    return;
  }
  WipeOnExit decodedGuard{decoded};

  TssHandle out = 0;
  TssStatus status = tss_handle_import(
      static_cast<const uint8_t *>(decoded.bytes),
      static_cast<size_t>(decoded.length),
      suiteValue,
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
    RejectBridgeError(reject, @"missing libtss version", TSS_ERR_INTERNAL_PANIC);
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
    uint8_t suiteValue = 0;
    if (!CheckedSuite(suite, &suiteValue, reject)) { return; }
    NSData *msgData = DecodeBase64(message, reject);
    if (msgData == nil) { return; }
    NSData *sigData = DecodeBase64(signature, reject);
    if (sigData == nil) { return; }
    NSData *pkData = DecodeBase64(publicKey, reject);
    if (pkData == nil) { return; }

    TssSlice msgSlice = { .data = (const uint8_t *)msgData.bytes, .len = msgData.length };
    TssSlice sigSlice = { .data = (const uint8_t *)sigData.bytes, .len = sigData.length };
    TssSlice pkSlice = { .data = (const uint8_t *)pkData.bytes, .len = pkData.length };

    bool result = tss_verify(suiteValue, msgSlice, sigSlice, pkSlice);
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
    RejectBridgeError(reject, [NSString stringWithFormat:@"Keychain SecItemAdd failed: %d", (int)ks],
                      TSS_ERR_INTERNAL_PANIC);
    return;
  }

  resolve(uuid);
}

RCT_EXPORT_METHOD(importKeyShareSecure:(nonnull NSNumber *)suite
                  keychainId:(NSString *)keychainId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
{
  // Validate the suite before reading the secret from the keychain.
  uint8_t suiteValue = 0;
  if (!CheckedSuite(suite, &suiteValue, reject)) {
    return;
  }
  if (keychainId == nil) {
    RejectBridgeError(reject, @"keychainId is required");
    return;
  }

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
    RejectBridgeError(reject, [NSString stringWithFormat:@"Keychain SecItemCopyMatching failed: %d", (int)ks],
                      ks == errSecItemNotFound ? TSS_ERR_INVALID_CONFIG : TSS_ERR_INTERNAL_PANIC);
    return;
  }

  NSData *keychainData = (__bridge_transfer NSData *)result;

  // Copy into a mutable buffer we own so we can safely wipe after import.
  // SecItemCopyMatching returns an immutable NSData whose backing memory may
  // not be safely writable (memset on it is technically UB). The mutable copy
  // is guaranteed heap-writable. The original NSData is released by ARC.
  NSMutableData *mutableCopy = [keychainData mutableCopy];
  keychainData = nil;  // release immutable copy early

  TssHandle out = 0;
  TssStatus status = tss_handle_import(
      static_cast<const uint8_t *>(mutableCopy.bytes),
      static_cast<size_t>(mutableCopy.length),
      suiteValue,
      &out);

  memset_s(mutableCopy.mutableBytes, mutableCopy.length, 0, mutableCopy.length);

  if (status != TSS_OK) {
    RejectStatus(reject, status);
    return;
  }

  resolve(HandleString(out));
}

@end
