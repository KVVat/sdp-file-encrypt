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

package com.android.niapsec.encryption.internal

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class RawEncryptionProvider(
    private val context: Context,
    private val keyAliasPrefix: String,
    private val unlockedDeviceRequired: Boolean
) : EncryptionProvider {
    //A fixed prefix for aliases to determine that the keys is managed by this provider.
    private val KEY_ALIAS_PREFIX = "raw_provider_key_${keyAliasPrefix}_"
    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
    private val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
    private val TRANSFORMATION = "$KEY_ALGORITHM/$BLOCK_MODE/$PADDING"

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }


    private fun generateEphemeralSoftwareKey(keyAlias:String):SecretKey {

        val keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, "AndroidOpenSSL")

        keyGenerator.init(256)
        //Generate it with a new alias
        val secretKey = keyGenerator.generateKey()
        val secretKeyEntry =
            KeyStore.SecretKeyEntry(secretKey)

        // Set the alias of the entry in Android KeyStore where the key will appear
        // and the constraints (purposes) in the constructor of the Builder
        keyStore.setEntry(
            keyAlias, secretKeyEntry,
            KeyProtection.Builder((KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT))
                .setEncryptionPaddings(PADDING)
                .setBlockModes(BLOCK_MODE)
                .setUnlockedDeviceRequired(unlockedDeviceRequired)
                .build()
        )

        return secretKey
    }

    private fun generateKey(keyAlias:String) {
        val keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(BLOCK_MODE)
            .setEncryptionPaddings(PADDING)
            .setKeySize(256)
            .setUnlockedDeviceRequired(unlockedDeviceRequired)
            .build()
        keyGenerator.init(spec)
        keyGenerator.generateKey()
    }

    private fun getSecretKey(keyAlias:String): SecretKey {
        return keyStore.getKey(keyAlias, null) as SecretKey
    }

    private fun encrypt(plaintext: ByteArray): ByteArray {

        val keyAlias = KEY_ALIAS_PREFIX + UUID.randomUUID().toString()

        val cipher = Cipher.getInstance(TRANSFORMATION)

        val secretKey: SecretKey = generateEphemeralSoftwareKey(keyAlias)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val spec = cipher.parameters.getParameterSpec(IvParameterSpec::class.java);
        val iv = spec.iv;
        val aliasBytes = keyAlias.toByteArray(Charsets.UTF_8)

        val header = ByteBuffer.allocate(4 + aliasBytes.size + 4 + iv.size)
            .putInt(aliasBytes.size)
            .put(aliasBytes)
            .putInt(iv.size)
            .put(iv)
            .array()

        val ciphertext = cipher.doFinal(plaintext)

        return header + ciphertext
    }

    private fun decryptToBytes(ciphertext: ByteArray): ByteArray {

        val buffer = ByteBuffer.wrap(ciphertext)

        val aliasLength = buffer.int
        if (aliasLength <= 0 || aliasLength > buffer.remaining()) throw GeneralSecurityException("Invalid alias length")
        val aliasBytes = ByteArray(aliasLength)
        buffer.get(aliasBytes)
        val keyAlias = String(aliasBytes, Charsets.UTF_8)

        val ivLength = buffer.int
        if (ivLength <= 0 || ivLength > buffer.remaining()) throw GeneralSecurityException("Invalid IV length")
        val iv = ByteArray(ivLength)
        buffer.get(iv)

        val cipher = Cipher.getInstance(TRANSFORMATION)

        val actualCiphertext = ByteArray(buffer.remaining())
        buffer.get(actualCiphertext) // This line was missing

        val secretKey = getSecretKey(keyAlias)
        val spec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        return cipher.doFinal(actualCiphertext)
    }
    override fun encrypt(file: File): OutputStream {
        return object : ByteArrayOutputStream() {
            override fun close() {
                super.close()
                val plaintext = toByteArray()
                val encryptedData = encrypt(plaintext)
                file.writeBytes(encryptedData)
            }
        }
    }

    override fun encrypt(plaintext: String): ByteArray {
        return encrypt(plaintext.toByteArray())
    }

    override fun decrypt(file: File): InputStream {
        val fileBytes = file.readBytes()
        val plaintextBytes = decryptToBytes(fileBytes)
        return ByteArrayInputStream(plaintextBytes)
    }

    override fun decrypt(ciphertext: ByteArray): String {
        val plaintextBytes = decryptToBytes(ciphertext)
        return String(plaintextBytes)
    }

    override fun destroy() {
        try {
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith(KEY_ALIAS_PREFIX)) {
                    keyStore.deleteEntry(alias)
                }
            }
        } catch (e: Exception) {
            Log.e("RawEncryptionProvider", "Failed to destroy keys", e)
        }
    }
}
