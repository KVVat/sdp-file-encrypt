package com.android.niapsec.encryption.internal

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class RawEncryptionProvider(
    private val context: Context,
    private val keyAlias: String,
    private val unlockedDeviceRequired: Boolean
) : EncryptionProvider {

    private val ANDROID_KEYSTORE = "AndroidKeyStore"
    private val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
    private val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
    private val TRANSFORMATION = "$KEY_ALGORITHM/$BLOCK_MODE/$PADDING"

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    init {
        if (!keyStore.containsAlias(keyAlias)) {
            //generateKey()
        }
    }

    private fun generateEphemeralSoftwareKey():SecretKey {

        val keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM, "AndroidOpenSSL")

        keyGenerator.init(256)
        //Generate it with a new alias
        val secretKey = keyGenerator.generateKey()
        val secretKeyEntry =
            KeyStore.SecretKeyEntry(secretKey)
        //Remove
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }

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

    private fun generateKey() {
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

    private fun getSecretKey(): SecretKey {
        return keyStore.getKey(keyAlias, null) as SecretKey
    }

    private fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val secretKey: SecretKey = generateEphemeralSoftwareKey()

        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val spec = cipher.parameters.getParameterSpec(IvParameterSpec::class.java);
        val iv = spec.iv;

        val ciphertext = cipher.doFinal(plaintext)

        val result = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(ciphertext, 0, result, iv.size, ciphertext.size)
        return result
    }

    private fun decryptToBytes(ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)

        val ivLength = cipher.blockSize
        if (ivLength <= 0) {
            throw GeneralSecurityException("Could not determine IV length from cipher")
        }

        if (ciphertext.size <= ivLength) {
            throw GeneralSecurityException("Invalid ciphertext: too short to contain IV and data")
        }

        val iv = ciphertext.copyOfRange(0, ivLength)
        val actualCiphertext = ciphertext.copyOfRange(ivLength, ciphertext.size)

        val spec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)

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
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }
}
