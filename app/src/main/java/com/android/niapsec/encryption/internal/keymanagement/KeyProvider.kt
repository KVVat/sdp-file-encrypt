package com.android.niapsec.encryption.internal.keymanagement

import com.google.crypto.tink.Aead

/**
 * A common interface for key providers, allowing different underlying key management
 * strategies (hardware-backed, software-only, etc.) to be used interchangeably.
 */
interface KeyProvider {
    /**
     * Retrieves the AEAD primitive for performing cryptographic operations.
     */
    fun getAead(): Aead

    fun getCachedAead(): Aead


    fun getUnlockDeviceRequired():Boolean
    /**
     * Destroys all cryptographic material associated with this provider.
     */
    fun destroy()
}
