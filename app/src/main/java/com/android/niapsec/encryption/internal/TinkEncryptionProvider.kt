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
import com.android.niapsec.encryption.internal.keymanagement.KeyProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException

class TinkEncryptionProvider(
    private val context: Context,
    val keyProvider: KeyProvider
) : EncryptionProvider {

    private val encryptionFlag = byteArrayOf(0x0)

    /**
     * Encrypts with the given key provider for file operations.
     */
    override fun encrypt(file: File): OutputStream {
        val aead = keyProvider.getAead()
        return object : ByteArrayOutputStream() {
            override fun close() {
                super.close()
                val plaintext = toByteArray()
                val ciphertext = aead.encrypt(plaintext, encryptionFlag)
                file.writeBytes(encryptionFlag + ciphertext)
            }
        }
    }

    /**
     * Encrypts a plaintext string into a ciphertext byte array.
     */
    override fun encrypt(plaintext: String): ByteArray {


        val aead = keyProvider.getAead()

        val ciphertext = aead.encrypt(plaintext.toByteArray(), encryptionFlag)
        return encryptionFlag + ciphertext
    }

    /**
     * Smart decryption method for file operations.
     */
    override fun decrypt(file: File): InputStream {
        val fileBytes = file.readBytes()
        val plaintext = decrypt(fileBytes)
        return ByteArrayInputStream(plaintext.toByteArray())
    }

    /**
     * Decrypts a ciphertext byte array into a plaintext string.
     */
    override fun decrypt(ciphertext: ByteArray): String {
        if (ciphertext.isEmpty()) {
            throw GeneralSecurityException("Cannot decrypt empty data.")
        }

        val flag = ciphertext.copyOfRange(0, 1)
        val actualCiphertext = ciphertext.copyOfRange(1, ciphertext.size)

        if (!flag.contentEquals(encryptionFlag)) {
            throw GeneralSecurityException("Invalid encryption flag found in data.")
        }

        val aead = keyProvider.getAead()
        val plaintext = aead.decrypt(actualCiphertext, encryptionFlag)
        return String(plaintext)
    }

    override fun destroy() {
        keyProvider.destroy()
    }
}
