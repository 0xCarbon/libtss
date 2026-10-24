package com.libtss;

import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.Nullable;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import java.security.KeyStore;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public final class LibtssModule extends ReactContextBaseJavaModule {
    static {
        System.loadLibrary("libtss-jni");
    }

    private static final int INVALID_CONFIG = 1;

    private interface NativeCall<T> {
        T run() throws Exception;
    }

    public LibtssModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "Libtss";
    }

    private void reject(Promise promise, Throwable error) {
        if (error instanceof LibtssException) {
            LibtssException nativeError = (LibtssException) error;
            WritableMap userInfo = Arguments.createMap();
            userInfo.putInt("code", nativeError.getNativeCode());

            int[] culprits = nativeError.getCulprits();
            if (culprits != null) {
                WritableArray culpritArray = Arguments.createArray();
                for (int culprit : culprits) {
                    culpritArray.pushInt(culprit);
                }
                userInfo.putArray("culprits", culpritArray);
            }

            Integer bannedParty = nativeError.getBannedParty();
            if (bannedParty != null) {
                userInfo.putInt("bannedParty", bannedParty);
            }

            promise.reject("E_LIBTSS", nativeError.getMessage(), nativeError, userInfo);
            return;
        }

        if (error instanceof IllegalArgumentException) {
            // Argument checks done in the bridge (ranges, missing values)
            // map to INVALID_CONFIG so JS sees a regular TssError code.
            WritableMap userInfo = Arguments.createMap();
            userInfo.putInt("code", INVALID_CONFIG);
            promise.reject("E_LIBTSS", error.getMessage(), error, userInfo);
            return;
        }

        promise.reject("E_LIBTSS", error);
    }

    private void resolve(Promise promise, NativeCall<Object> call) {
        try {
            promise.resolve(call.run());
        } catch (Throwable error) {
            reject(promise, error);
        }
    }

    // JS numbers arrive as doubles. Reject non-integers and out-of-range
    // values instead of letting a cast truncate them.
    private static int checkedInt(double value, int min, int max, String name) {
        if (Double.isNaN(value) || value != Math.rint(value) || value < min || value > max) {
            throw new IllegalArgumentException(name + " must be an integer in [" + min + ", " + max + "]");
        }
        return (int) value;
    }

    private static int suiteValue(double value) {
        return checkedInt(value, 0, 255, "suite");
    }

    private static int identifierValue(double value, String name) {
        return checkedInt(value, 1, 0xFFFF, name);
    }

    @Nullable
    private static int[] identifiers(@Nullable ReadableArray values, String name) {
        if (values == null) {
            return null;
        }
        int[] out = new int[values.size()];
        for (int i = 0; i < values.size(); i++) {
            out[i] = identifierValue(values.getDouble(i), name);
        }
        return out;
    }

    private WritableMap sessionInitResult(String[] value) {
        WritableMap result = Arguments.createMap();
        result.putString("handle", value[0]);
        result.putString("messages", value[1]);
        return result;
    }

    private WritableMap roundResult(Object[] value) {
        WritableMap result = Arguments.createMap();
        result.putBoolean("complete", (Boolean) value[0]);
        if (value.length > 1 && value[1] instanceof String) {
            result.putString("messages", (String) value[1]);
        }
        if (value.length > 2 && value[2] instanceof String) {
            result.putString("keyShareHandle", (String) value[2]);
        }
        if (value.length > 3 && value[3] instanceof String) {
            result.putString("pubkeyPackage", (String) value[3]);
        }
        if (value.length > 4 && value[4] instanceof String) {
            result.putString("signature", (String) value[4]);
        }
        if (value.length > 5 && value[5] instanceof Integer) {
            result.putInt("recoveryId", (Integer) value[5]);
        }
        return result;
    }

    @ReactMethod
    public void dkgNew(double suite, double selfId, double maxSigners, double minSigners, @Nullable String sessionId, Promise promise) {
        resolve(promise, () -> sessionInitResult(nativeDkgNew(
                suiteValue(suite),
                identifierValue(selfId, "selfId"),
                checkedInt(maxSigners, 1, 0xFFFF, "maxSigners"),
                checkedInt(minSigners, 1, 0xFFFF, "minSigners"),
                sessionId)));
    }

    @ReactMethod
    public void dkgNext(String handle, String messages, Promise promise) {
        resolve(promise, () -> roundResult(nativeDkgNext(handle, messages)));
    }

    @ReactMethod
    public void signNew(String keyShareHandle, String message, @Nullable ReadableArray counterparties, @Nullable String signId, Promise promise) {
        resolve(promise, () -> sessionInitResult(
                nativeSignNew(keyShareHandle, message, identifiers(counterparties, "counterparty"), signId)));
    }

    @ReactMethod
    public void signNext(String handle, String messages, Promise promise) {
        resolve(promise, () -> roundResult(nativeSignNext(handle, messages)));
    }

    @ReactMethod
    public void refreshNew(String keyShareHandle, @Nullable ReadableArray participants, Promise promise) {
        resolve(promise, () -> sessionInitResult(
                nativeRefreshNew(keyShareHandle, identifiers(participants, "participant"))));
    }

    @ReactMethod
    public void refreshNewDkls(String keyShareHandle, String sessionId, Promise promise) {
        resolve(promise, () -> sessionInitResult(nativeRefreshNewDkls(keyShareHandle, sessionId)));
    }

    @ReactMethod
    public void repairHelperTerm(String keyShareHandle, ReadableArray helpers, double target, String repairId, Promise promise) {
        resolve(promise, () -> {
            if (helpers == null) {
                throw new IllegalArgumentException("helpers is required");
            }
            return nativeRepairHelperTerm(
                    keyShareHandle, identifiers(helpers, "helper"), identifierValue(target, "target"), repairId);
        });
    }

    @ReactMethod
    public void repairAssemble(double suite, String pubkeyPackage, double target, String messages, Promise promise) {
        resolve(promise, () -> nativeRepairAssemble(
                suiteValue(suite), pubkeyPackage, identifierValue(target, "target"), messages));
    }

    @ReactMethod
    public void bolt3Derive(String keyShareHandle, String perCommitmentPoint, Promise promise) {
        resolve(promise, () -> nativeBolt3Derive(keyShareHandle, perCommitmentPoint));
    }

    @ReactMethod
    public void bolt3DeriveRevocation(String keyShareHandle, String perCommitmentPoint, String perCommitmentSecret, Promise promise) {
        resolve(promise, () -> nativeBolt3DeriveRevocation(keyShareHandle, perCommitmentPoint, perCommitmentSecret));
    }

    @ReactMethod
    public void bolt3DerivePubkeyPackage(String pubkeyPackage, String perCommitmentPoint, Promise promise) {
        resolve(promise, () -> nativeBolt3DerivePubkeyPackage(pubkeyPackage, perCommitmentPoint, false));
    }

    @ReactMethod
    public void bolt3DeriveRevocationPubkeyPackage(String pubkeyPackage, String perCommitmentPoint, Promise promise) {
        resolve(promise, () -> nativeBolt3DerivePubkeyPackage(pubkeyPackage, perCommitmentPoint, true));
    }

    @ReactMethod
    public void refreshReceiver(String keyShareHandle, double dealer, Promise promise) {
        resolve(promise, () -> nativeRefreshReceiver(keyShareHandle, identifierValue(dealer, "dealer")));
    }

    @ReactMethod
    public void refreshNext(String handle, String messages, Promise promise) {
        resolve(promise, () -> roundResult(nativeRefreshNext(handle, messages)));
    }

    @ReactMethod
    public void handleFree(String handle, Promise promise) {
        resolve(promise, () -> {
            nativeHandleFree(handle);
            return null;
        });
    }

    @ReactMethod
    public void sessionFree(String handle, Promise promise) {
        resolve(promise, () -> {
            nativeSessionFree(handle);
            return null;
        });
    }

    @ReactMethod
    public void handleIdentifier(String handle, Promise promise) {
        resolve(promise, () -> nativeHandleIdentifier(handle));
    }

    @ReactMethod
    public void handleVerifyingShare(String handle, Promise promise) {
        resolve(promise, () -> nativeHandleVerifyingShare(handle));
    }

    @ReactMethod
    public void handleGroupKey(String handle, Promise promise) {
        resolve(promise, () -> nativeHandleGroupKey(handle));
    }

    @ReactMethod
    public void handleChainCode(String handle, Promise promise) {
        resolve(promise, () -> nativeHandleChainCode(handle));
    }

    @ReactMethod
    public void handlePubkeyPackage(String handle, Promise promise) {
        resolve(promise, () -> nativeHandlePubkeyPackage(handle));
    }

    @ReactMethod
    public void handleCiphersuite(String handle, Promise promise) {
        resolve(promise, () -> nativeHandleCiphersuite(handle));
    }

    @ReactMethod
    public void exportKeyShare(String handle, Promise promise) {
        resolve(promise, () -> nativeExportKeyShare(handle));
    }

    @ReactMethod
    public void importKeyShare(double suite, String data, Promise promise) {
        resolve(promise, () -> nativeImportKeyShare(suiteValue(suite), data));
    }

    @ReactMethod
    public void version(Promise promise) {
        resolve(promise, LibtssModule::nativeVersion);
    }

    private static final String KEYSTORE_ALIAS = "libtss_share_key";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;

    private SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEYSTORE_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(KEYSTORE_ALIAS, null)).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build());
        return generator.generateKey();
    }

    private SharedPreferences getSecurePrefs() {
        return getReactApplicationContext()
                .getSharedPreferences("libtss_secure_shares", 0);
    }

    @ReactMethod
    public void initialize(ReadableMap options, Promise promise) {
        resolve(promise, () -> {
            int flags = options.hasKey("mlock") && options.getBoolean("mlock") ? 1 : 0;
            nativeInit(flags);
            return null;
        });
    }

    @ReactMethod
    public void exportKeyShareSecure(String handle, Promise promise) {
        resolve(promise, () -> {
            byte[] plaintext = nativeExportKeyShareRaw(handle);
            try {
                SecretKey key = getOrCreateKey();
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] iv = cipher.getIV();
                if (iv.length != GCM_IV_LENGTH) {
                    throw new RuntimeException("unexpected GCM IV length: " + iv.length);
                }
                byte[] ciphertext = cipher.doFinal(plaintext);
                byte[] combined = new byte[iv.length + ciphertext.length];
                System.arraycopy(iv, 0, combined, 0, iv.length);
                System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
                String id = UUID.randomUUID().toString();
                boolean committed = getSecurePrefs().edit()
                        .putString(id, Base64.encodeToString(combined, Base64.NO_WRAP))
                        .commit();
                if (!committed) {
                    throw new RuntimeException("failed to persist secure key share to SharedPreferences");
                }
                return id;
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        });
    }

    @ReactMethod
    public void importKeyShareSecure(double suite, String keychainId, Promise promise) {
        resolve(promise, () -> {
            int suiteInt = suiteValue(suite);
            String encoded = getSecurePrefs().getString(keychainId, null);
            if (encoded == null) {
                throw new IllegalArgumentException("keychain entry not found: " + keychainId);
            }
            byte[] combined = Base64.decode(encoded, Base64.NO_WRAP);
            if (combined.length < GCM_IV_LENGTH) {
                throw new IllegalArgumentException("corrupted keychain entry: data too short");
            }
            byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);
            SecretKey key = getOrCreateKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] decrypted = cipher.doFinal(ciphertext);
            try {
                return nativeImportKeyShareRaw(suiteInt, decrypted);
            } finally {
                Arrays.fill(decrypted, (byte) 0);
            }
        });
    }

    private static native void nativeInit(int flags);
    private static native byte[] nativeExportKeyShareRaw(String handle);
    private static native String nativeImportKeyShareRaw(int suite, byte[] data);
    private static native String[] nativeDkgNew(int suite, int selfId, int maxSigners, int minSigners, @Nullable String sessionId);
    private static native Object[] nativeDkgNext(String handle, String messages);
    private static native String[] nativeSignNew(String keyShareHandle, String message, @Nullable int[] counterparties, @Nullable String signId);
    private static native Object[] nativeSignNext(String handle, String messages);
    private static native String[] nativeRefreshNew(String keyShareHandle, @Nullable int[] participants);
    private static native String nativeRefreshReceiver(String keyShareHandle, int dealer);
    private static native String[] nativeRefreshNewDkls(String keyShareHandle, String sessionId);
    private static native String nativeRepairHelperTerm(String keyShareHandle, int[] helpers, int target, String repairId);
    private static native String nativeRepairAssemble(int suite, String pubkeyPackage, int target, String messages);
    private static native String nativeBolt3Derive(String keyShareHandle, String perCommitmentPoint);
    private static native String nativeBolt3DeriveRevocation(String keyShareHandle, String perCommitmentPoint, String perCommitmentSecret);
    private static native String nativeBolt3DerivePubkeyPackage(String pubkeyPackage, String perCommitmentPoint, boolean revocation);
    private static native Object[] nativeRefreshNext(String handle, String messages);
    private static native void nativeHandleFree(String handle);
    private static native void nativeSessionFree(String handle);
    private static native double nativeHandleIdentifier(String handle);
    private static native String nativeHandleVerifyingShare(String handle);
    private static native String nativeHandleGroupKey(String handle);
    private static native String nativeHandleChainCode(String handle);
    private static native String nativeHandlePubkeyPackage(String handle);
    private static native double nativeHandleCiphersuite(String handle);
    private static native String nativeExportKeyShare(String handle);
    private static native String nativeImportKeyShare(int suite, String data);
    private static native String nativeVersion();
    @ReactMethod
    public void verify(double suite, String message, String signature, String publicKey, Promise promise) {
        resolve(promise, () -> nativeVerify(suiteValue(suite), message, signature, publicKey));
    }

    private static native boolean nativeVerify(int suite, String message, String signature, String publicKey);

}
