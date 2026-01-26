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
}
