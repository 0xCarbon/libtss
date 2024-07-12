package com.zerox.rtntss;

import com.sun.jna.Library
import com.sun.jna.Native

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.zerox.rtntss.NativeTssSpec
import android.os.Build

private interface LibTssRust : Library {
    fun dkls_dkg_phase1(json: String): String
    fun dkls_dkg_phase2(json_in: String): String
    fun dkls_dkg_phase3(json_in: String): String
    fun dkls_dkg_phase4(json_in: String): String

    fun dkls_sign_phase1(json_in: String): String
    fun dkls_sign_phase2(json_in: String): String
    fun dkls_sign_phase3(json_in: String): String
    fun dkls_sign_phase4(json_in: String): String

    fun dkls_verify_ecdsa_signature(json_in: String): String

    fun dkls_derivation(json_in: String): String

    fun dkls_re_key(json_in: String): String
}

class TssModule(reactContext: ReactApplicationContext) : NativeTssSpec(reactContext) {
    companion object {
        const val NAME = "ZeroxTSS"
    }

    override fun getName() = NAME

    private val libTss: LibTssRust = Native.load("ffi_tss", LibTssRust::class.java)

    // DKLs23 Keygen
    override fun DKLsDkgPhase1(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_dkg_phase1(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_DKG_PHASE1_ERROR", "An error occurred during DKLsDkgPhase1: ${e.message}", e)
        }
    }

    override fun DKLsDkgPhase2(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_dkg_phase2(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_DKG_PHASE2_ERROR", "An error occurred during DKLsDkgPhase2: ${e.message}", e)
        }
    }

    override fun DKLsDkgPhase3(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_dkg_phase3(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_DKG_PHASE3_ERROR", "An error occurred during DKLsDkgPhase3: ${e.message}", e)
        }
    }

    override fun DKLsDkgPhase4(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_dkg_phase4(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_DKG_PHASE4_ERROR", "An error occurred during DKLsDkgPhase4: ${e.message}", e)
        }
    }

    // DKLs23 Sign
    override fun DKLsSignPhase1(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_sign_phase1(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_SIGN_PHASE1_ERROR", "An error occurred during DKLsSignPhase1: ${e.message}", e)
        }
    }

    override fun DKLsSignPhase2(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_sign_phase2(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_SIGN_PHASE2_ERROR", "An error occurred during DKLsSignPhase2: ${e.message}", e)
        }
    }

    override fun DKLsSignPhase3(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_sign_phase3(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_SIGN_PHASE3_ERROR", "An error occurred during DKLsSignPhase3: ${e.message}", e)
        }
    }

    override fun DKLsSignPhase4(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_sign_phase4(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_SIGN_PHASE4_ERROR", "An error occurred during DKLsSignPhase4: ${e.message}", e)
        }
    }

    // DKLs23 Verify ECDSA signature
    override fun DKLsVerifyECDSASignature(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_verify_ecdsa_signature(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_VERIFY_ECDSA_SIGNATURE_ERROR", "An error occurred during DKLsVerifyECDSASignature: ${e.message}", e)
        }
    }

    // DKLs23 derivation
    override fun DKLsDerivation(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_derivation(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_DERIVATION_ERROR", "An error occurred during DKLsDerivation: ${e.message}", e)
        }
    }

    // DKLs23 Rekey
    override fun DKLsReKey(data: String, promise: Promise) {
        try {
            val result = libTss.dkls_re_key(data)
            promise.resolve(result)
        } catch (e: Exception) {
            e.printStackTrace()
            promise.reject("DKLS_RE_KEY_ERROR", "An error occurred during DKLsReKey: ${e.message}", e)
        }
    }
}
