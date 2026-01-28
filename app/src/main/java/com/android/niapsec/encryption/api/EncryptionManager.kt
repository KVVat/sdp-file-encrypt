package com.android.niapsec.encryption.api

import android.content.Context
import android.util.Base64
import com.android.niapsec.encryption.internal.EncryptionProvider
import com.android.niapsec.encryption.internal.RawEncryptionProvider
import com.android.niapsec.encryption.internal.TinkEncryptionProvider
import com.android.niapsec.encryption.internal.keymanagement.HybridKeyProvider
import com.android.niapsec.encryption.internal.keymanagement.P521KeyProvider
import com.android.niapsec.encryption.internal.keymanagement.SecureKeyProvider
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * Manages encryption and decryption operations for files and strings using a configurable KeyProvider.
 */
class EncryptionManager(
    context: Context,
    masterKeyUri: String, // Used for both SECURE and INSECURE to derive a unique preference file name
    providerType: KeyProviderType = KeyProviderType.SECURE,
    unlockedDeviceRequired: Boolean = false, // Only applies to the SECURE provider
    private val encryptionProvider: EncryptionProvider = when (providerType) {
        KeyProviderType.RAW ->
            RawEncryptionProvider(context, masterKeyUri.replace("android-keystore://", ""), unlockedDeviceRequired)
        else ->
            TinkEncryptionProvider(context,
                when (providerType) {
                    KeyProviderType.SECURE ->
                        SecureKeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
                    KeyProviderType.P521 ->
                        P521KeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
                    KeyProviderType.HYBRID ->
                        HybridKeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
                    else -> throw IllegalArgumentException("Invalid provider type: $providerType")
                }
            )
    }
) {

    fun destroy() {
        encryptionProvider.destroy()
    }

    /**
     * Encrypts a file using the configured key provider.
     */
    fun encryptToFile(file: File): OutputStream {
        return encryptionProvider.encrypt(file)
    }

    /**
     * Decrypts the file using the configured key provider.
     */
    fun decryptFromFile(file: File): InputStream {
        return encryptionProvider.decrypt(file)
    }

    /**
     * Encrypts a string and returns it as a Base64-encoded ciphertext.
     */
    fun encryptToString(plaintext: String): String {
        val ciphertext = encryptionProvider.encrypt(plaintext)
        return Base64.encodeToString(ciphertext, Base64.DEFAULT)
    }

    /**
     * Decrypts a Base64-encoded ciphertext string and returns the plaintext.
     */
    fun decryptFromString(ciphertext: String): String {
        val ciphertextBytes = Base64.decode(ciphertext, Base64.DEFAULT)
        return encryptionProvider.decrypt(ciphertextBytes)
    }
}
