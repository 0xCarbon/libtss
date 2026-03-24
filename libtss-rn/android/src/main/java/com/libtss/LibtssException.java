package com.libtss;

import androidx.annotation.Nullable;

public final class LibtssException extends RuntimeException {
    private final int nativeCode;
    @Nullable private final int[] culprits;
    @Nullable private final Integer bannedParty;

    public LibtssException(int nativeCode, String message, @Nullable int[] culprits, @Nullable Integer bannedParty) {
        super(message);
        this.nativeCode = nativeCode;
        this.culprits = culprits;
        this.bannedParty = bannedParty;
    }

    public int getNativeCode() {
        return nativeCode;
    }

    @Nullable
    public int[] getCulprits() {
        return culprits;
    }

    @Nullable
    public Integer getBannedParty() {
        return bannedParty;
    }
}
