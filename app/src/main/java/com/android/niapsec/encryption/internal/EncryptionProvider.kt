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

import java.io.File
import java.io.InputStream
import java.io.OutputStream

/**
 * An interface for providing encryption and decryption operations.
 */
interface EncryptionProvider {

    /**
     * Encrypts a file and returns an OutputStream to write the plaintext to.
     */
    fun encrypt(file: File): OutputStream

    /**
     * Encrypts a plaintext string into a ciphertext byte array.
     */
    fun encrypt(plaintext: String): ByteArray

    /**
     * Decrypts a file and returns an InputStream to read the plaintext from.
     */
    fun decrypt(file: File): InputStream

    /**
     * Decrypts a ciphertext byte array into a plaintext string.
     */
    fun decrypt(ciphertext: ByteArray): String

    /**
     * Destroys any cryptographic material associated with this provider.
     */
    fun destroy()
}
