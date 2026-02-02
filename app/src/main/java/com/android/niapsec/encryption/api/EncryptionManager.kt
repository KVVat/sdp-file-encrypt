/*
* Copyright (C) 2026 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.android.niapsec.encryption.api

import android.content.Context
import android.util.Base64
import com.android.niapsec.encryption.internal.EncryptionProvider
import com.android.niapsec.encryption.internal.TinkEncryptionProvider
import com.android.niapsec.encryption.internal.keymanagement.HybridKeyProvider
import com.android.niapsec.encryption.internal.keymanagement.RawHybridKeyProvider
import com.android.niapsec.encryption.internal.keymanagement.RawKeyProvider
import com.android.niapsec.encryption.internal.keymanagement.SecureKeyProvider
import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * Manages encryption and decryption operations for files and strings using a configurable KeyProvider.
 */
class EncryptionManager(
    context: Context,
    masterKeyUri: String, // Used to derive a unique preference file name
    providerType: KeyProviderType = KeyProviderType.HYBRID,
    unlockedDeviceRequired: Boolean = false, // Only applies to SECURE and RAW providers
    private val encryptionProvider: EncryptionProvider = TinkEncryptionProvider(context,
        when (providerType) {
            KeyProviderType.RAW ->
                RawKeyProvider(context, masterKeyUri.replace("android-keystore://", ""), unlockedDeviceRequired)
            KeyProviderType.HYBRID ->
                HybridKeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
            KeyProviderType.SECURE ->
                SecureKeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
            KeyProviderType.RAW_HYBRID ->
                RawHybridKeyProvider(context, masterKeyUri, unlockedDeviceRequired, "tink_keyset_${masterKeyUri.replace("android-keystore://", "")}")
        }
    )
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
