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
    private val keyProvider: KeyProvider
) {

    private val encryptionFlag = byteArrayOf(0x0)

    /**
     * Encrypts with the given key provider for file operations.
     */
    fun encrypt(file: File): OutputStream {
        val aead = keyProvider.getCachedAead();
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
    fun encrypt(plaintext: String): ByteArray {


        val aead = keyProvider.getCachedAead()

        val ciphertext = aead.encrypt(plaintext.toByteArray(), encryptionFlag)
        return encryptionFlag + ciphertext
    }

    /**
     * Smart decryption method for file operations.
     */
    fun decrypt(file: File): InputStream {
        val fileBytes = file.readBytes()
        val plaintext = decrypt(fileBytes)
        return ByteArrayInputStream(plaintext.toByteArray())
    }

    /**
     * Decrypts a ciphertext byte array into a plaintext string.
     */
    fun decrypt(ciphertext: ByteArray): String {
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
}
