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
constexpr TssStatus TSS_ERR_INVALID_CONFIG = 1;
constexpr TssStatus TSS_ERR_HANDLE_INVALID = 7;
constexpr TssStatus TSS_ERR_ABORT = 10;
constexpr TssStatus TSS_ERR_ABORT_BAN = 11;
constexpr uint8_t TSS_NO_RECOVERY_ID = 255;

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
TssStatus tss_handle_chain_code(TssHandle handle, TssBuffer* out);
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
TssStatus tss_sign_next_recoverable(
    TssHandle session,
    TssSlice messages,
    TssBuffer* out_signature,
    uint8_t* out_recovery_id,
    TssBuffer* out_messages,
    bool* out_complete);
TssStatus tss_refresh_new(
    TssHandle key_share,
    const uint16_t* participants,
    size_t participants_len,
    TssHandle* out_session,
    TssBuffer* out_messages);
TssStatus tss_refresh_receiver(TssHandle key_share, TssHandle* out_session);
TssStatus tss_refresh_new_dkls(
    TssHandle key_share,
    const uint8_t* session_id,
    size_t session_id_len,
    TssHandle* out_session,
    TssBuffer* out_messages);
TssStatus tss_repair_helper_term(
    TssHandle key_share,
    const uint16_t* helpers,
    size_t helpers_len,
    uint16_t target,
    TssSlice repair_id,
    TssBuffer* out_messages);
TssStatus tss_repair_assemble(
    uint8_t suite,
    TssSlice pubkey_package,
    uint16_t target,
    TssSlice messages,
    TssHandle* out_handle);
TssStatus tss_bolt3_derive(TssHandle key_share, TssSlice per_commitment_point, TssHandle* out_handle);
TssStatus tss_bolt3_derive_revocation(
    TssHandle key_share,
    TssSlice per_commitment_point,
    TssSlice per_commitment_secret,
    TssHandle* out_handle);
TssStatus tss_bolt3_derive_pubkey_package(
    TssSlice pubkey_package,
    TssSlice per_commitment_point,
    TssBuffer* out_pubkey_package);
TssStatus tss_bolt3_derive_revocation_pubkey_package(
    TssSlice pubkey_package,
    TssSlice per_commitment_point,
    TssBuffer* out_pubkey_package);
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

// Throws LibtssException with a status code for errors detected in the
// bridge itself (bad ranges, malformed base64, unparsable handles), so JS
// sees a regular TssError code instead of INTERNAL_PANIC.
void throw_bridge_error(JNIEnv* env, TssStatus code, const std::string& message) {
    jclass exception_class = env->FindClass("com/libtss/LibtssException");
    if (exception_class == nullptr) {
        env->ExceptionClear();
        throw_with_message(env, "java/lang/IllegalArgumentException", message);
        return;
    }
    jmethodID ctor = env->GetMethodID(exception_class, "<init>", "(ILjava/lang/String;[ILjava/lang/Integer;)V");
    if (ctor == nullptr) {
        env->ExceptionClear();
        throw_with_message(env, "java/lang/IllegalArgumentException", message);
        return;
    }
    jstring message_string = env->NewStringUTF(message.c_str());
    if (message_string == nullptr) {
        return;
    }
    jobject exception = env->NewObject(exception_class, ctor, static_cast<jint>(code), message_string, nullptr, nullptr);
    if (exception == nullptr) {
        return;
    }
    env->Throw(static_cast<jthrowable>(exception));
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
            throw_bridge_error(env, TSS_ERR_HANDLE_INVALID, "handle is required");
        }
        return false;
    }

    errno = 0;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(chars.get(), &end, 10);
    if (errno != 0 || end == chars.get() || end == nullptr || *end != '\0') {
        throw_bridge_error(env, TSS_ERR_HANDLE_INVALID, "invalid handle");
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

void wipe_raw(void* data, size_t len) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

template <typename T>
void wipe(std::vector<T>& values) {
    wipe_raw(values.data(), values.size() * sizeof(T));
}

// Vector that zeroes its contents on destruction. Bridge payloads (protocol
// messages, key shares, repair terms, BOLT 3 secrets) and their base64 text
// all pass through it. Callers size it once with resize() so no reallocation
// leaves an unwiped copy behind.
template <typename T>
struct WipedVector : std::vector<T> {
    WipedVector() = default;
    WipedVector(const WipedVector&) = delete;
    WipedVector& operator=(const WipedVector&) = delete;
    ~WipedVector() { wipe(*this); }
};

using WipedBytes = WipedVector<uint8_t>;

// Zeroes a Java byte array in place. Safe to call with a pending exception:
// the exception is saved, cleared for the JNI calls and rethrown.
void wipe_java_array(JNIEnv* env, jbyteArray array) {
    if (array == nullptr) {
        return;
    }
    jthrowable pending = env->ExceptionOccurred();
    if (pending != nullptr) {
        env->ExceptionClear();
    }
    jsize len = env->GetArrayLength(array);
    if (len > 0) {
        void* data = env->GetPrimitiveArrayCritical(array, nullptr);
        if (data != nullptr) {
            wipe_raw(data, static_cast<size_t>(len));
            env->ReleasePrimitiveArrayCritical(array, data, 0);
        }
    }
    if (pending != nullptr) {
        env->ExceptionClear();
        env->Throw(pending);
        env->DeleteLocalRef(pending);
    }
}

bool require_non_null(JNIEnv* env, const void* value, const char* name) {
    if (value != nullptr) {
        return true;
    }
    throw_bridge_error(env, TSS_ERR_INVALID_CONFIG, std::string(name) + " is required");
    return false;
}

// Range-checks an integer argument before it is narrowed for the C API.
bool check_range(JNIEnv* env, jint value, jint min, jint max, const char* name) {
    if (value >= min && value <= max) {
        return true;
    }
    throw_bridge_error(
        env,
        TSS_ERR_INVALID_CONFIG,
        std::string(name) + " must be in [" + std::to_string(min) + ", " + std::to_string(max) + "]");
    return false;
}

// Copies a Java int[] of identifiers into a uint16 vector, rejecting values
// outside [1, 0xFFFF].
bool read_identifiers(JNIEnv* env, jintArray values, const char* name, std::vector<uint16_t>* out) {
    if (!require_non_null(env, values, name)) {
        return false;
    }
    jsize n = env->GetArrayLength(values);
    std::vector<jint> tmp(static_cast<size_t>(n));
    if (n > 0) {
        env->GetIntArrayRegion(values, 0, n, tmp.data());
        if (env->ExceptionCheck()) {
            return false;
        }
    }
    out->clear();
    out->reserve(static_cast<size_t>(n));
    for (jint value : tmp) {
        if (!check_range(env, value, 1, 0xFFFF, name)) {
            return false;
        }
        out->push_back(static_cast<uint16_t>(value));
    }
    return true;
}

int base64_value(jchar c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

// Decodes standard padded base64 directly into `out`. The text is copied
// into a wiped buffer and decoded natively, so no Java-side decoder leaves
// an intermediate plaintext array behind. Malformed input (bad length,
// characters, padding position, or non-zero trailing bits) is rejected.
bool decode_base64(JNIEnv* env, jstring value, WipedBytes* out) {
    if (!require_non_null(env, value, "base64 input")) {
        return false;
    }
    jsize length = env->GetStringLength(value);
    WipedVector<jchar> text;
    text.resize(static_cast<size_t>(length));
    if (length > 0) {
        env->GetStringRegion(value, 0, length, text.data());
        if (env->ExceptionCheck()) {
            return false;
        }
    }

    size_t len = text.size();
    size_t padding = 0;
    if (len % 4 == 0 && len > 0) {
        if (text[len - 1] == '=') {
            padding++;
            if (text[len - 2] == '=') padding++;
        }
    }
    if (len % 4 != 0) {
        throw_bridge_error(env, TSS_ERR_INVALID_CONFIG, "invalid base64 input");
        return false;
    }

    out->clear();
    out->resize(len / 4 * 3 - padding);
    size_t written = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t quad = 0;
        for (size_t j = 0; j < 4; ++j) {
            jchar c = text[i + j];
            int v = (c == '=' && i + j >= len - padding) ? 0 : base64_value(c);
            if (v < 0) {
                wipe(*out);
                throw_bridge_error(env, TSS_ERR_INVALID_CONFIG, "invalid base64 input");
                return false;
            }
            quad = (quad << 6) | static_cast<uint32_t>(v);
        }
        uint8_t chunk[3] = {
            static_cast<uint8_t>(quad >> 16), static_cast<uint8_t>(quad >> 8), static_cast<uint8_t>(quad)};
        bool trailing_ok = i + 4 < len || padding == 0 || (padding == 1 ? chunk[2] == 0 : chunk[1] == 0);
        for (size_t k = 0; k < 3 && written < out->size(); ++k) {
            (*out)[written++] = chunk[k];
        }
        wipe_raw(chunk, sizeof chunk);
        quad = 0;
        if (!trailing_ok) {
            wipe(*out);
            throw_bridge_error(env, TSS_ERR_INVALID_CONFIG, "invalid base64 input");
            return false;
        }
    }
    return true;
}

// Encodes to standard padded base64 natively into a wiped buffer, so the
// only remaining copy is the returned Java string.
jstring encode_base64(JNIEnv* env, const uint8_t* data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    WipedVector<char> text;
    text.resize((len + 2) / 3 * 4 + 1);
    size_t pos = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) triple |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) triple |= static_cast<uint32_t>(data[i + 2]);
        text[pos++] = alphabet[(triple >> 18) & 0x3F];
        text[pos++] = alphabet[(triple >> 12) & 0x3F];
        text[pos++] = i + 1 < len ? alphabet[(triple >> 6) & 0x3F] : '=';
        text[pos++] = i + 2 < len ? alphabet[triple & 0x3F] : '=';
        triple = 0;
    }
    text[pos] = '\0';
    return env->NewStringUTF(text.data());
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

// Owns a native session created by this call until it is handed to Java,
// so every failure path after creation frees it.
struct OwnedSession {
    TssHandle value = 0;
    OwnedSession() = default;
    OwnedSession(const OwnedSession&) = delete;
    OwnedSession& operator=(const OwnedSession&) = delete;
    ~OwnedSession() {
        if (value != 0) {
            tss_session_free(value);
        }
    }
    void release() { value = 0; }
};

// Owns a native key share handle created by this call until it is handed to
// Java.
struct OwnedHandle {
    TssHandle value = 0;
    OwnedHandle() = default;
    OwnedHandle(const OwnedHandle&) = delete;
    OwnedHandle& operator=(const OwnedHandle&) = delete;
    ~OwnedHandle() {
        if (value != 0) {
            tss_handle_free(value);
        }
    }
    void release() { value = 0; }
};

// Frees (and thereby zeroes) a native output buffer on every exit path.
struct OwnedBuffer {
    TssBuffer value{nullptr, 0};
    OwnedBuffer() = default;
    OwnedBuffer(const OwnedBuffer&) = delete;
    OwnedBuffer& operator=(const OwnedBuffer&) = delete;
    ~OwnedBuffer() { release_buffer(value); }
};

// Converts a handle created by this call to a Java string and transfers
// ownership to Java only once the string exists.
jstring take_handle(JNIEnv* env, OwnedHandle& handle) {
    jstring text = handle_to_jstring(env, handle.value);
    if (text == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }
    handle.release();
    return text;
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

jobject integer_object(JNIEnv* env, jint value) {
    jclass integer_class = require_class(env, "java/lang/Integer");
    if (integer_class == nullptr) {
        return nullptr;
    }
    jmethodID value_of = env->GetStaticMethodID(integer_class, "valueOf", "(I)Ljava/lang/Integer;");
    if (value_of == nullptr) {
        return nullptr;
    }
    return env->CallStaticObjectMethod(integer_class, value_of, value);
}

// Builds the [handle, messages] result and transfers the session to Java
// only once the result exists.
jobjectArray make_session_init_result(JNIEnv* env, OwnedSession& session, jstring messages) {
    if (messages == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }
    jclass string_class = require_class(env, "java/lang/String");
    if (string_class == nullptr) {
        return nullptr;
    }

    jobjectArray result = env->NewObjectArray(2, string_class, nullptr);
    if (result == nullptr) {
        return nullptr;
    }

    jstring handle_string = handle_to_jstring(env, session.value);
    if (handle_string == nullptr || env->ExceptionCheck()) {
        return nullptr;
    }

    env->SetObjectArrayElement(result, 0, handle_string);
    env->SetObjectArrayElement(result, 1, messages);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    session.release();
    return result;
}

jobjectArray make_round_result(
    JNIEnv* env,
    bool complete,
    jstring messages,
    jstring key_share_handle,
    jstring pubkey_package,
    jstring signature,
    jobject recovery_id = nullptr) {
    jclass object_class = require_class(env, "java/lang/Object");
    if (object_class == nullptr) {
        return nullptr;
    }

    jobjectArray result = env->NewObjectArray(6, object_class, nullptr);
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
    env->SetObjectArrayElement(result, 5, recovery_id);
    if (env->ExceptionCheck()) {
        return nullptr;
    }
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
    if (!check_range(env, suite, 0, 0xFF, "suite") || !check_range(env, selfId, 1, 0xFFFF, "selfId") ||
        !check_range(env, maxSigners, 1, 0xFFFF, "maxSigners") ||
        !check_range(env, minSigners, 1, 0xFFFF, "minSigners")) {
        return nullptr;
    }
    WipedBytes session_id_bytes;
    const uint8_t* session_id_ptr = nullptr;
    size_t session_id_len = 0;
    if (sessionId != nullptr) {
        if (!decode_base64(env, sessionId, &session_id_bytes)) {
            return nullptr;
        }
        session_id_ptr = session_id_bytes.empty() ? nullptr : session_id_bytes.data();
        session_id_len = session_id_bytes.size();
    }

    OwnedSession session;
    OwnedBuffer messages;
    TssStatus status = tss_dkg_new(
        static_cast<uint8_t>(suite),
        static_cast<uint16_t>(selfId),
        static_cast<uint16_t>(maxSigners),
        static_cast<uint16_t>(minSigners),
        session_id_ptr,
        session_id_len,
        &session.value,
        &messages.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return make_session_init_result(env, session, take_base64(env, messages.value));
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeDkgNext(JNIEnv* env, jclass, jstring handle, jstring messages) {
    TssHandle session = 0;
    if (!parse_handle(env, handle, &session)) {
        return nullptr;
    }

    WipedBytes message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    OwnedHandle key_share;
    OwnedBuffer pubkey_package;
    OwnedBuffer out_messages;
    bool complete = false;
    TssStatus status = tss_dkg_next(
        session,
        make_slice(message_bytes),
        &key_share.value,
        &pubkey_package.value,
        &out_messages.value,
        &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages.value);
        jstring encoded_pubkey_package = take_base64(env, pubkey_package.value);
        if (encoded_pubkey_package == nullptr || env->ExceptionCheck()) {
            return nullptr;
        }
        jstring key_share_handle = handle_to_jstring(env, key_share.value);
        if (key_share_handle == nullptr || env->ExceptionCheck()) {
            return nullptr;
        }
        jobjectArray result =
            make_round_result(env, true, nullptr, key_share_handle, encoded_pubkey_package, nullptr);
        if (result != nullptr) {
            key_share.release();
        }
        return result;
    }

    release_buffer(pubkey_package.value);
    jstring encoded_messages = take_base64(env, out_messages.value);
    if (encoded_messages == nullptr || env->ExceptionCheck()) {
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

    WipedBytes message_bytes;
    if (!decode_base64(env, message, &message_bytes)) {
        return nullptr;
    }

    std::vector<uint16_t> cp_vec;
    const uint16_t* cp_ptr = nullptr;
    size_t cp_len = 0;
    if (counterparties != nullptr) {
        if (!read_identifiers(env, counterparties, "counterparty", &cp_vec)) {
            return nullptr;
        }
        cp_ptr = cp_vec.empty() ? nullptr : cp_vec.data();
        cp_len = cp_vec.size();
    }

    WipedBytes sign_id_bytes;
    const uint8_t* sign_id_ptr = nullptr;
    size_t sign_id_len = 0;
    if (signId != nullptr) {
        if (!decode_base64(env, signId, &sign_id_bytes)) {
            return nullptr;
        }
        sign_id_ptr = sign_id_bytes.empty() ? nullptr : sign_id_bytes.data();
        sign_id_len = sign_id_bytes.size();
    }

    OwnedSession session;
    OwnedBuffer out_messages;
    TssStatus status = tss_sign_new(
        key_share,
        make_slice(message_bytes),
        cp_ptr,
        cp_len,
        sign_id_ptr,
        sign_id_len,
        &session.value,
        &out_messages.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return make_session_init_result(env, session, take_base64(env, out_messages.value));
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeSignNext(JNIEnv* env, jclass, jstring handle, jstring messages) {
    TssHandle session = 0;
    if (!parse_handle(env, handle, &session)) {
        return nullptr;
    }

    WipedBytes message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    OwnedBuffer signature;
    uint8_t recovery_id = TSS_NO_RECOVERY_ID;
    OwnedBuffer out_messages;
    bool complete = false;
    TssStatus status = tss_sign_next_recoverable(
        session, make_slice(message_bytes), &signature.value, &recovery_id, &out_messages.value, &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages.value);
        jstring encoded_signature = take_base64(env, signature.value);
        if (encoded_signature == nullptr || env->ExceptionCheck()) {
            return nullptr;
        }
        jobject recovery_object = nullptr;
        if (recovery_id != TSS_NO_RECOVERY_ID) {
            recovery_object = integer_object(env, static_cast<jint>(recovery_id));
            if (recovery_object == nullptr || env->ExceptionCheck()) {
                return nullptr;
            }
        }
        return make_round_result(env, true, nullptr, nullptr, nullptr, encoded_signature, recovery_object);
    }

    release_buffer(signature.value);
    jstring encoded_messages = take_base64(env, out_messages.value);
    if (encoded_messages == nullptr || env->ExceptionCheck()) {
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
        if (!read_identifiers(env, participants, "participant", &p_vec)) {
            return nullptr;
        }
        p_ptr = p_vec.empty() ? nullptr : p_vec.data();
        p_len = p_vec.size();
    }

    OwnedSession session;
    OwnedBuffer messages;
    TssStatus status = tss_refresh_new(key_share, p_ptr, p_len, &session.value, &messages.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return make_session_init_result(env, session, take_base64(env, messages.value));
}

namespace {

TssSlice slice_of(const std::vector<uint8_t>& bytes) {
    return TssSlice{bytes.empty() ? nullptr : bytes.data(), bytes.size()};
}

}  // namespace

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_libtss_LibtssModule_nativeRefreshNewDkls(JNIEnv* env, jclass, jstring keyShareHandle, jstring sessionId) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }
    WipedBytes sid;
    if (!decode_base64(env, sessionId, &sid)) {
        return nullptr;
    }
    OwnedSession session;
    OwnedBuffer messages;
    TssStatus status = tss_refresh_new_dkls(
        key_share, sid.empty() ? nullptr : sid.data(), sid.size(), &session.value, &messages.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return make_session_init_result(env, session, take_base64(env, messages.value));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeRepairHelperTerm(
    JNIEnv* env, jclass, jstring keyShareHandle, jintArray helpers, jint target, jstring repairId) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }
    std::vector<uint16_t> ids;
    if (!read_identifiers(env, helpers, "helper", &ids) || !check_range(env, target, 1, 0xFFFF, "target")) {
        return nullptr;
    }
    WipedBytes repair_id;
    if (!decode_base64(env, repairId, &repair_id)) {
        return nullptr;
    }
    TssBuffer out{nullptr, 0};
    TssStatus status = tss_repair_helper_term(
        key_share, ids.data(), ids.size(), static_cast<uint16_t>(target), slice_of(repair_id), &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return take_base64(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeRepairAssemble(
    JNIEnv* env, jclass, jint suite, jstring pubkeyPackage, jint target, jstring messages) {
    if (!check_range(env, suite, 0, 0xFF, "suite") || !check_range(env, target, 1, 0xFFFF, "target")) {
        return nullptr;
    }
    WipedBytes package;
    WipedBytes blob;
    if (!decode_base64(env, pubkeyPackage, &package) || !decode_base64(env, messages, &blob)) {
        return nullptr;
    }
    OwnedHandle out;
    TssStatus status = tss_repair_assemble(
        static_cast<uint8_t>(suite), slice_of(package), static_cast<uint16_t>(target), slice_of(blob), &out.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return take_handle(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeBolt3Derive(JNIEnv* env, jclass, jstring keyShareHandle, jstring perCommitmentPoint) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }
    WipedBytes point;
    if (!decode_base64(env, perCommitmentPoint, &point)) {
        return nullptr;
    }
    OwnedHandle out;
    TssStatus status = tss_bolt3_derive(key_share, slice_of(point), &out.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return take_handle(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeBolt3DeriveRevocation(
    JNIEnv* env, jclass, jstring keyShareHandle, jstring perCommitmentPoint, jstring perCommitmentSecret) {
    TssHandle key_share = 0;
    if (!parse_handle(env, keyShareHandle, &key_share)) {
        return nullptr;
    }
    WipedBytes point;
    WipedBytes secret;
    if (!decode_base64(env, perCommitmentPoint, &point) || !decode_base64(env, perCommitmentSecret, &secret)) {
        return nullptr;
    }
    OwnedHandle out;
    TssStatus status = tss_bolt3_derive_revocation(key_share, slice_of(point), slice_of(secret), &out.value);
    wipe(secret);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return take_handle(env, out);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeBolt3DerivePubkeyPackage(
    JNIEnv* env, jclass, jstring pubkeyPackage, jstring perCommitmentPoint, jboolean revocation) {
    WipedBytes package;
    WipedBytes point;
    if (!decode_base64(env, pubkeyPackage, &package) || !decode_base64(env, perCommitmentPoint, &point)) {
        return nullptr;
    }
    TssBuffer out{nullptr, 0};
    TssStatus status = revocation
        ? tss_bolt3_derive_revocation_pubkey_package(slice_of(package), slice_of(point), &out)
        : tss_bolt3_derive_pubkey_package(slice_of(package), slice_of(point), &out);
    if (!ensure_status(env, status)) {
        return nullptr;
    }
    return take_base64(env, out);
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

    WipedBytes message_bytes;
    if (!decode_base64(env, messages, &message_bytes)) {
        return nullptr;
    }

    OwnedHandle key_share;
    OwnedBuffer pubkey_package;
    OwnedBuffer out_messages;
    bool complete = false;
    TssStatus status = tss_refresh_next(
        session,
        make_slice(message_bytes),
        &key_share.value,
        &pubkey_package.value,
        &out_messages.value,
        &complete);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    if (complete) {
        release_buffer(out_messages.value);
        jstring encoded_pubkey_package = take_base64(env, pubkey_package.value);
        if (encoded_pubkey_package == nullptr || env->ExceptionCheck()) {
            return nullptr;
        }
        jstring key_share_handle = handle_to_jstring(env, key_share.value);
        if (key_share_handle == nullptr || env->ExceptionCheck()) {
            return nullptr;
        }
        jobjectArray result =
            make_round_result(env, true, nullptr, key_share_handle, encoded_pubkey_package, nullptr);
        if (result != nullptr) {
            key_share.release();
        }
        return result;
    }

    release_buffer(pubkey_package.value);
    jstring encoded_messages = take_base64(env, out_messages.value);
    if (encoded_messages == nullptr || env->ExceptionCheck()) {
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

extern "C" JNIEXPORT void JNICALL
Java_com_libtss_LibtssModule_nativeSessionFree(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return;
    }

    tss_session_free(parsed);
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
Java_com_libtss_LibtssModule_nativeHandleChainCode(JNIEnv* env, jclass, jstring handle) {
    TssHandle parsed = 0;
    if (!parse_handle(env, handle, &parsed)) {
        return nullptr;
    }

    TssBuffer out{nullptr, 0};
    TssStatus status = tss_handle_chain_code(parsed, &out);
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
    if (!check_range(env, suite, 0, 0xFF, "suite")) {
        return nullptr;
    }
    WipedBytes bytes;
    if (!decode_base64(env, data, &bytes)) {
        return nullptr;
    }

    OwnedHandle out;
    TssStatus status = tss_handle_import(
        bytes.empty() ? nullptr : bytes.data(),
        bytes.size(),
        static_cast<uint8_t>(suite),
        &out.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_handle(env, out);
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
    if (!check_range(env, suite, 0, 0xFF, "suite")) {
        return JNI_FALSE;
    }
    WipedBytes msg_vec;
    WipedBytes sig_vec;
    WipedBytes pk_vec;
    if (!decode_base64(env, message, &msg_vec) || !decode_base64(env, signature, &sig_vec) ||
        !decode_base64(env, publicKey, &pk_vec)) {
        return JNI_FALSE;
    }

    TssSlice msg_slice = slice_of(msg_vec);
    TssSlice sig_slice = slice_of(sig_vec);
    TssSlice pk_slice = slice_of(pk_vec);

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

    OwnedBuffer out;
    TssStatus status = tss_handle_export(parsed, &out.value);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    jbyteArray result = env->NewByteArray(static_cast<jsize>(out.value.len));
    if (result == nullptr) {
        return nullptr;
    }

    if (out.value.len > 0) {
        env->SetByteArrayRegion(result, 0, static_cast<jsize>(out.value.len),
                                reinterpret_cast<const jbyte*>(out.value.data));
        if (env->ExceptionCheck()) {
            wipe_java_array(env, result);
            return nullptr;
        }
    }
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_libtss_LibtssModule_nativeImportKeyShareRaw(JNIEnv* env, jclass, jint suite, jbyteArray data) {
    if (!check_range(env, suite, 0, 0xFF, "suite") || !require_non_null(env, data, "data")) {
        return nullptr;
    }
    jsize len = env->GetArrayLength(data);
    WipedBytes vec;
    vec.resize(static_cast<size_t>(len));
    if (len > 0) {
        env->GetByteArrayRegion(data, 0, len, reinterpret_cast<jbyte*>(vec.data()));
        if (env->ExceptionCheck()) {
            return nullptr;
        }
    }

    OwnedHandle out;
    TssStatus status = tss_handle_import(
        vec.empty() ? nullptr : vec.data(),
        vec.size(),
        static_cast<uint8_t>(suite),
        &out.value);
    wipe(vec);
    if (!ensure_status(env, status)) {
        return nullptr;
    }

    return take_handle(env, out);
}
