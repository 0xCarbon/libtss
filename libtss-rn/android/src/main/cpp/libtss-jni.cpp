#include <jni.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

using TssHandle = uint64_t;
using TssStatus = int32_t;

struct TssBuffer {
    uint8_t* data;
    size_t len;
};

struct TssSlice {
    const uint8_t* data;
    size_t len;
};

constexpr TssStatus TSS_OK = 0;
constexpr TssStatus TSS_ERR_ABORT = 10;
constexpr TssStatus TSS_ERR_ABORT_BAN = 11;
constexpr jint ANDROID_BASE64_NO_WRAP = 2;

extern "C" {
const char* tss_last_error(void);
size_t tss_last_error_len(void);
size_t tss_abort_culprit_count(void);
uint16_t tss_abort_culprit(size_t index);
uint16_t tss_abort_banned_party(void);
TssStatus tss_init(uint32_t flags);
void tss_buffer_free(TssBuffer* buf);
void tss_handle_free(TssHandle handle);
TssStatus tss_handle_identifier(TssHandle handle, uint16_t* out_id);
TssStatus tss_handle_verifying_share(TssHandle handle, TssBuffer* out);
TssStatus tss_handle_group_key(TssHandle handle, TssBuffer* out);
TssStatus tss_handle_pubkey_package(TssHandle handle, TssBuffer* out);
uint8_t tss_handle_ciphersuite(TssHandle handle);
TssStatus tss_handle_export(TssHandle handle, TssBuffer* out);
TssStatus tss_handle_import(const uint8_t* data, size_t data_len, uint8_t suite, TssHandle* out_handle);
bool tss_verify(uint8_t suite, TssSlice message, TssSlice signature, TssSlice public_key);
TssStatus tss_dkg_new(
    uint8_t suite,
    uint16_t self_id,
    uint16_t max_signers,
    uint16_t min_signers,
    const uint8_t* session_id,
    size_t session_id_len,
    TssHandle* out_session,
    TssBuffer* out_messages);
TssStatus tss_dkg_next(
    TssHandle session,
    TssSlice messages,
    TssHandle* out_key_share,
    TssBuffer* out_pubkey_package,
    TssBuffer* out_messages,
    bool* out_complete);
TssStatus tss_sign_new(
    TssHandle key_share,
    TssSlice message,
    const uint16_t* counterparties,
    size_t counterparties_len,
    const uint8_t* sign_id,
    size_t sign_id_len,
    TssHandle* out_session,
    TssBuffer* out_messages);
TssStatus tss_sign_next(
    TssHandle session,
    TssSlice messages,
    TssBuffer* out_signature,
    TssBuffer* out_messages,
    bool* out_complete);
TssStatus tss_refresh_new(
    TssHandle key_share,
    const uint16_t* participants,
    size_t participants_len,
    TssHandle* out_session,
    TssBuffer* out_messages);
TssStatus tss_refresh_receiver(TssHandle key_share, TssHandle* out_session);
TssStatus tss_refresh_next(
    TssHandle session,
    TssSlice messages,
    TssHandle* out_key_share,
    TssBuffer* out_pubkey_package,
    TssBuffer* out_messages,
    bool* out_complete);
void tss_session_free(TssHandle session);
const char* tss_version(void);
}

class UtfChars {
  public:
    UtfChars(JNIEnv* env, jstring value) : env_(env), value_(value), chars_(value == nullptr ? nullptr : env->GetStringUTFChars(value, nullptr)) {}

    ~UtfChars() {
        if (value_ != nullptr && chars_ != nullptr) {
            env_->ReleaseStringUTFChars(value_, chars_);
        }
    }

    const char* get() const { return chars_; }

  private:
    JNIEnv* env_;
    jstring value_;
    const char* chars_;
};

std::string last_error_message() {
    const char* message = tss_last_error();
    if (message == nullptr) {
        return "libtss native call failed";
    }

    size_t len = tss_last_error_len();
    if (len == 0) {
        return std::string(message);
    }

    return std::string(message, len);
}

void throw_with_message(JNIEnv* env, const char* class_name, const std::string& message) {
    jclass cls = env->FindClass(class_name);
    if (cls != nullptr) {
        env->ThrowNew(cls, message.c_str());
    }
}

void throw_libtss_exception(JNIEnv* env, TssStatus status) {
    std::string message = last_error_message();

    std::vector<jint> culprits;
    if (status == TSS_ERR_ABORT || status == TSS_ERR_ABORT_BAN) {
        size_t culprit_count = tss_abort_culprit_count();
        culprits.reserve(culprit_count);
        for (size_t index = 0; index < culprit_count; ++index) {
            culprits.push_back(static_cast<jint>(tss_abort_culprit(index)));
        }
    }

    jclass exception_class = env->FindClass("com/libtss/LibtssException");
    if (exception_class == nullptr) {
        throw_with_message(env, "java/lang/RuntimeException", message);
        return;
    }

    jmethodID ctor = env->GetMethodID(exception_class, "<init>", "(ILjava/lang/String;[ILjava/lang/Integer;)V");
    if (ctor == nullptr) {
        throw_with_message(env, "java/lang/RuntimeException", message);
        return;
    }

    jintArray culprit_array = nullptr;
    if (!culprits.empty()) {
        culprit_array = env->NewIntArray(static_cast<jsize>(culprits.size()));
        if (culprit_array == nullptr) {
            return;
        }
        env->SetIntArrayRegion(culprit_array, 0, static_cast<jsize>(culprits.size()), culprits.data());
    }

    jobject banned_party = nullptr;
    if (status == TSS_ERR_ABORT_BAN) {
        uint16_t banned = tss_abort_banned_party();
        if (banned != 0) {
            jclass integer_class = env->FindClass("java/lang/Integer");
            if (integer_class == nullptr) {
                return;
            }
            jmethodID value_of = env->GetStaticMethodID(integer_class, "valueOf", "(I)Ljava/lang/Integer;");
            if (value_of == nullptr) {
                return;
            }
            banned_party = env->CallStaticObjectMethod(integer_class, value_of, static_cast<jint>(banned));
            if (env->ExceptionCheck()) {
                return;
            }
        }
    }

    jstring message_string = env->NewStringUTF(message.c_str());
    if (message_string == nullptr) {
        return;
    }

    jobject exception =
        env->NewObject(exception_class, ctor, static_cast<jint>(status), message_string, culprit_array, banned_party);
    if (exception == nullptr) {
        return;
    }

    env->Throw(static_cast<jthrowable>(exception));
}

bool parse_handle(JNIEnv* env, jstring value, TssHandle* out_handle) {
    UtfChars chars(env, value);
    if (chars.get() == nullptr) {
        if (!env->ExceptionCheck()) {
            throw_with_message(env, "java/lang/IllegalArgumentException", "handle is required");
        }
        return false;
    }

    errno = 0;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(chars.get(), &end, 10);
    if (errno != 0 || end == chars.get() || end == nullptr || *end != '\0') {
        throw_with_message(env, "java/lang/IllegalArgumentException", "invalid handle");
        return false;
    }

    *out_handle = static_cast<TssHandle>(parsed);
    return true;
}

TssSlice make_slice(const std::vector<uint8_t>& bytes) {
    return TssSlice{bytes.empty() ? nullptr : bytes.data(), bytes.size()};
}

jclass require_class(JNIEnv* env, const char* name) {
    jclass cls = env->FindClass(name);
    return cls;
}

bool decode_base64(JNIEnv* env, jstring value, std::vector<uint8_t>* out) {
    jclass base64_class = require_class(env, "android/util/Base64");
    if (base64_class == nullptr) {
        return false;
    }

    jmethodID decode = env->GetStaticMethodID(base64_class, "decode", "(Ljava/lang/String;I)[B");
    if (decode == nullptr) {
        return false;
    }

    jbyteArray bytes = static_cast<jbyteArray>(
        env->CallStaticObjectMethod(base64_class, decode, value, ANDROID_BASE64_NO_WRAP));
    if (env->ExceptionCheck()) {
        return false;
    }
    if (bytes == nullptr) {
        throw_with_message(env, "java/lang/IllegalArgumentException", "invalid base64 input");
        return false;
    }

    jsize len = env->GetArrayLength(bytes);
    out->resize(static_cast<size_t>(len));
    if (len > 0) {
        env->GetByteArrayRegion(bytes, 0, len, reinterpret_cast<jbyte*>(out->data()));
    }
    return !env->ExceptionCheck();
}

jstring encode_base64(JNIEnv* env, const uint8_t* data, size_t len) {
    jbyteArray bytes = env->NewByteArray(static_cast<jsize>(len));
    if (bytes == nullptr) {
        return nullptr;
    }

    if (len > 0) {
        env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(len), reinterpret_cast<const jbyte*>(data));
        if (env->ExceptionCheck()) {
            return nullptr;
        }
    }

    jclass base64_class = require_class(env, "android/util/Base64");
    if (base64_class == nullptr) {
        return nullptr;
    }

    jmethodID encode_to_string =
        env->GetStaticMethodID(base64_class, "encodeToString", "([BI)Ljava/lang/String;");
    if (encode_to_string == nullptr) {
        return nullptr;
    }

    return static_cast<jstring>(
        env->CallStaticObjectMethod(base64_class, encode_to_string, bytes, ANDROID_BASE64_NO_WRAP));
}

jstring take_base64(JNIEnv* env, TssBuffer& buffer) {
    jstring encoded = encode_base64(env, buffer.data, buffer.len);
    tss_buffer_free(&buffer);
    return encoded;
}

void release_buffer(TssBuffer& buffer) {
    if (buffer.data != nullptr || buffer.len != 0) {
        tss_buffer_free(&buffer);
    }
}

jstring handle_to_jstring(JNIEnv* env, TssHandle handle) {
    std::string text = std::to_string(handle);
    return env->NewStringUTF(text.c_str());
}

jobject boolean_object(JNIEnv* env, bool value) {
    jclass boolean_class = require_class(env, "java/lang/Boolean");
    if (boolean_class == nullptr) {
        return nullptr;
    }

    jmethodID value_of = env->GetStaticMethodID(boolean_class, "valueOf", "(Z)Ljava/lang/Boolean;");
    if (value_of == nullptr) {
        return nullptr;
    }

    return env->CallStaticObjectMethod(boolean_class, value_of, static_cast<jboolean>(value));
}

jobjectArray make_session_init_result(JNIEnv* env, TssHandle handle, jstring messages) {
    jclass string_class = require_class(env, "java/lang/String");
    if (string_class == nullptr) {
        return nullptr;
    }

    jobjectArray result = env->NewObjectArray(2, string_class, nullptr);
    if (result == nullptr) {
        return nullptr;
    }

    jstring handle_string = handle_to_jstring(env, handle);
    if (handle_string == nullptr) {
        return nullptr;
    }

    env->SetObjectArrayElement(result, 0, handle_string);
    env->SetObjectArrayElement(result, 1, messages);
    return result;
}

jobjectArray make_round_result(
    JNIEnv* env,
    bool complete,
    jstring messages,
    jstring key_share_handle,
    jstring pubkey_package,
    jstring signature) {
    jclass object_class = require_class(env, "java/lang/Object");
    if (object_class == nullptr) {
        return nullptr;
    }

    jobjectArray result = env->NewObjectArray(5, object_class, nullptr);
    if (result == nullptr) {
        return nullptr;
    }

    jobject complete_object = boolean_object(env, complete);
    if (complete_object == nullptr) {
        return nullptr;
    }

    env->SetObjectArrayElement(result, 0, complete_object);
    env->SetObjectArrayElement(result, 1, messages);
    env->SetObjectArrayElement(result, 2, key_share_handle);
    env->SetObjectArrayElement(result, 3, pubkey_package);
    env->SetObjectArrayElement(result, 4, signature);
    return result;
}

bool ensure_status(JNIEnv* env, TssStatus status) {
    if (status == TSS_OK) {
        return true;
    }

    throw_libtss_exception(env, status);
    return false;
}

}  // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeDkgNew(
    JNIEnv* env,
    jclass,
    jint suite,
    jint selfId,
    jint maxSigners,
    jint minSigners,
    jstring sessionId) {
    std::vector<uint8_t> session_id_bytes;
    const uint8_t* session_id_ptr = nullptr;
    size_t session_id_len = 0;
    if (sessionId != nullptr) {
        if (!decode_base64(env, sessionId, &session_id_bytes)) {
            return nullptr;
        }
        session_id_ptr = session_id_bytes.empty() ? nullptr : session_id_bytes.data();
        session_id_len = session_id_bytes.size();
    }

    TssHandle session = 0;
    TssBuffer messages{nullptr, 0};
    TssStatus status = tss_dkg_new(
        static_cast<uint8_t>(suite),
        static_cast<uint16_t>(selfId),
        static_cast<uint16_t>(maxSigners),
        static_cast<uint16_t>(minSigners),
        session_id_ptr,
        session_id_len,
        &session,
        &messages);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    jstring encoded_messages = take_base64(env, messages);
    if (encoded_messages == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }

    return make_session_init_result(env, session, encoded_messages);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeDkgNext(JNIEnv* env, jclass, jstring handle, jstring messages) {
    TssHandle session = 0;
    if (!parse_handle(env, handle, &session)) {
        return nullptr;
    }

    std::vector<uint8_t> message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    TssHandle key_share = 0;
    TssBuffer pubkey_package{nullptr, 0};
    TssBuffer out_messages{nullptr, 0};
    bool complete = false;
    TssStatus status = tss_dkg_next(
        session,
        make_slice(message_bytes),
        &key_share,
        &pubkey_package,
        &out_messages,
        &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages);
        jstring key_share_handle = handle_to_jstring(env, key_share);
        jstring encoded_pubkey_package = take_base64(env, pubkey_package);
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        return make_round_result(env, true, nullptr, key_share_handle, encoded_pubkey_package, nullptr);
    }

    release_buffer(pubkey_package);
    jstring encoded_messages = take_base64(env, out_messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return make_round_result(env, false, encoded_messages, nullptr, nullptr, nullptr);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeSignNew(
    JNIEnv* env,
    jclass,
    jstring keyShareHandle,
    jstring message,
    jintArray counterparties,
    jstring signId) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }

    std::vector<uint8_t> message_bytes;
    if (!decode_base64(env, message, &message_bytes)) {
        return nullptr;
    }

    std::vector<uint16_t> cp_vec;
    const uint16_t* cp_ptr = nullptr;
    size_t cp_len = 0;
    if (counterparties != nullptr) {
        jsize n = env->GetArrayLength(counterparties);
        std::vector<jint> tmp(static_cast<size_t>(n));
        env->GetIntArrayRegion(counterparties, 0, n, tmp.data());
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        cp_vec.reserve(static_cast<size_t>(n));
        for (jsize i = 0; i < n; ++i) {
            cp_vec.push_back(static_cast<uint16_t>(tmp[static_cast<size_t>(i)]));
        }
        cp_ptr = cp_vec.data();
        cp_len = cp_vec.size();
    }

    std::vector<uint8_t> sign_id_bytes;
    const uint8_t* sign_id_ptr = nullptr;
    size_t sign_id_len = 0;
    if (signId != nullptr) {
        if (!decode_base64(env, signId, &sign_id_bytes)) {
            return nullptr;
        }
        sign_id_ptr = sign_id_bytes.empty() ? nullptr : sign_id_bytes.data();
        sign_id_len = sign_id_bytes.size();
    }

    TssHandle session = 0;
    TssBuffer out_messages{nullptr, 0};
    TssStatus status = tss_sign_new(
        key_share,
        make_slice(message_bytes),
        cp_ptr,
        cp_len,
        sign_id_ptr,
        sign_id_len,
        &session,
        &out_messages);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    jstring encoded_messages = take_base64(env, out_messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return make_session_init_result(env, session, encoded_messages);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeSignNext(JNIEnv* env, jclass, jstring handle, jstring messages) {
    TssHandle session = 0;
    if (!parse_handle(env, handle, &session)) {
        return nullptr;
    }

    std::vector<uint8_t> message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    TssBuffer signature{nullptr, 0};
    TssBuffer out_messages{nullptr, 0};
    bool complete = false;
    TssStatus status = tss_sign_next(session, make_slice(message_bytes), &signature, &out_messages, &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages);
        jstring encoded_signature = take_base64(env, signature);
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        return make_round_result(env, true, nullptr, nullptr, nullptr, encoded_signature);
    }

    release_buffer(signature);
    jstring encoded_messages = take_base64(env, out_messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return make_round_result(env, false, encoded_messages, nullptr, nullptr, nullptr);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeRefreshNew(JNIEnv* env, jclass, jstring keyShareHandle, jintArray participants) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }

    std::vector<uint16_t> p_vec;
    const uint16_t* p_ptr = nullptr;
    size_t p_len = 0;
    if (participants != nullptr) {
        jsize n = env->GetArrayLength(participants);
        std::vector<jint> tmp(static_cast<size_t>(n));
        env->GetIntArrayRegion(participants, 0, n, tmp.data());
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        p_vec.reserve(static_cast<size_t>(n));
        for (jsize i = 0; i < n; ++i) {
            p_vec.push_back(static_cast<uint16_t>(tmp[static_cast<size_t>(i)]));
        }
        p_ptr = p_vec.data();
        p_len = p_vec.size();
    }

    TssHandle session = 0;
    TssBuffer messages{nullptr, 0};
    TssStatus status = tss_refresh_new(key_share, p_ptr, p_len, &session, &messages);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    jstring encoded_messages = take_base64(env, messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return make_session_init_result(env, session, encoded_messages);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeRefreshReceiver(JNIEnv* env, jclass, jstring keyShareHandle) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }

    TssHandle session = 0;
    TssStatus status = tss_refresh_receiver(key_share, &session);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return handle_to_jstring(env, session);
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeRefreshNext(JNIEnv* env, jclass, jstring handle, jstring messages) {
    TssHandle session = 0;
    if (!parse_handle(env, handle, &session)) {
        return nullptr;
    }

    std::vector<uint8_t> message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    TssHandle key_share = 0;
    TssBuffer pubkey_package{nullptr, 0};
    TssBuffer out_messages{nullptr, 0};
    bool complete = false;
    TssStatus status = tss_refresh_next(
        session,
        make_slice(message_bytes),
        &key_share,
        &pubkey_package,
        &out_messages,
        &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages);
        jstring key_share_handle = handle_to_jstring(env, key_share);
        jstring encoded_pubkey_package = take_base64(env, pubkey_package);
        if (env->ExceptionCheck()) {
            return nullptr;
        }
        return make_round_result(env, true, nullptr, key_share_handle, encoded_pubkey_package, nullptr);
    }

    release_buffer(pubkey_package);
    jstring encoded_messages = take_base64(env, out_messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    return make_round_result(env, false, encoded_messages, nullptr, nullptr, nullptr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_libtss_LibtssModule_nativeHandleFree(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return;
    }

    tss_handle_free(parsed);
}

extern "C" JNIEXPORT jdouble JNICALL
Java_com_libtss_LibtssModule_nativeHandleIdentifier(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return 0;
    }

    uint16_t identifier = 0;
    TssStatus status = tss_handle_identifier(parsed, &identifier);
    if (!ensure_status(env, status)) {
        return 0;
    }

    return static_cast<jdouble>(identifier);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeHandleVerifyingShare(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_verifying_share(parsed, &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_base64(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeHandleGroupKey(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_group_key(parsed, &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_base64(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeHandlePubkeyPackage(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_pubkey_package(parsed, &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_base64(env, out);
}

extern "C" JNIEXPORT jdouble JNICALL
Java_com_libtss_LibtssModule_nativeHandleCiphersuite(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return 0;
    }

    return static_cast<jdouble>(tss_handle_ciphersuite(parsed));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeExportKeyShare(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_export(parsed, &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_base64(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeImportKeyShare(JNIEnv* env, jclass, jint suite, jstring data) {
    std::vector<uint8_t> bytes;
    if (!decode_base64(env, data, &bytes)) {
        return nullptr;
    }

    TssHandle out = 0;
    TssStatus status = tss_handle_import(
        bytes.empty() ? nullptr : bytes.data(),
        bytes.size(),
        static_cast<uint8_t>(suite),
        &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return handle_to_jstring(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeVersion(JNIEnv* env, jclass) {
    const char* version = tss_version();
    if (version == nullptr) {
        return env->NewStringUTF("");
    }

    return env->NewStringUTF(version);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_libtss_LibtssModule_nativeVerify(JNIEnv* env, jclass, jint suite, jstring message, jstring signature, jstring publicKey) {
    auto decode = [env](jstring str) -> std::vector<uint8_t> {
        if (!str) return {};
        jclass base64_class = env->FindClass("android/util/Base64");
        jmethodID decode_method = env->GetStaticMethodID(base64_class, "decode", "(Ljava/lang/String;I)[B");
        auto decoded = (jbyteArray)env->CallStaticObjectMethod(base64_class, decode_method, str, ANDROID_BASE64_NO_WRAP);
        if (env->ExceptionCheck() || !decoded) {
            env->ExceptionClear();
            return {};
        }
        jsize len = env->GetArrayLength(decoded);
        std::vector<uint8_t> vec(len);
        env->GetByteArrayRegion(decoded, 0, len, reinterpret_cast<jbyte*>(vec.data()));
        return vec;
    };

    auto msg_vec = decode(message);
    auto sig_vec = decode(signature);
    auto pk_vec = decode(publicKey);

    TssSlice msg_slice{msg_vec.data(), msg_vec.size()};
    TssSlice sig_slice{sig_vec.data(), sig_vec.size()};
    TssSlice pk_slice{pk_vec.data(), pk_vec.size()};

    return tss_verify(static_cast<uint8_t>(suite), msg_slice, sig_slice, pk_slice) ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_libtss_LibtssModule_nativeInit(JNIEnv* env, jclass, jint flags) {
    TssStatus status = tss_init(static_cast<uint32_t>(flags));
    ensure_status(env, status);
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_libtss_LibtssModule_nativeExportKeyShareRaw(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_export(parsed, &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    jbyteArray result = env->NewByteArray(static_cast<jsize>(out.len));
    if (result == nullptr) {
        tss_buffer_free(&out);
        return nullptr;
    }

    if (out.len > 0) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(out.len),
                                reinterpret_cast<const jbyte*>(out.data));
    }
    tss_buffer_free(&out);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeImportKeyShareRaw(JNIEnv* env, jclass, jint suite, jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    std::vector<uint8_t> vec(static_cast<size_t>(len));
    if (len > 0) {
        env->GetByteArrayRegion(data, 0, len, reinterpret_cast<jbyte*>(vec.data()));
        if (env->ExceptionCheck()) {
            return nullptr;
        }
    }

    TssHandle out = 0;
    TssStatus status = tss_handle_import(
        vec.empty() ? nullptr : vec.data(),
        vec.size(),
        static_cast<uint8_t>(suite),
        &out);
    explicit_bzero(vec.data(), vec.size());
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return handle_to_jstring(env, out);
}
