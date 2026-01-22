package com.android.niapsec.demo

import android.content.Context
import android.content.SharedPreferences
import com.android.niapsec.encryption.api.EncryptionManager

/**
 * A wrapper for SharedPreferences that transparently encrypts and decrypts values.
 *
 * @param context The application context.
 * @param fileName The name of the SharedPreferences file.
 * @param encryptionManager The EncryptionManager instance to use for cryptographic operations.
 */
class EncryptedSharedPreferences(context: Context, fileName: String, private val encryptionManager: EncryptionManager) {

    private val sharedPreferences: SharedPreferences = context.getSharedPreferences(fileName, Context.MODE_PRIVATE)

    /**
     * Encrypts and saves a string value.
     */
    fun putString(key: String, value: String) {
        try {
            val encryptedValue = encryptionManager.encryptToString(value)
            sharedPreferences.edit().putString(key, encryptedValue).apply()
        } catch (e: Exception) {
            throw SecurityException("Failed to encrypt and save the value for key: $key", e)
        }
    }

    /**
     * Retrieves and decrypts a string value.
     * Returns the defaultValue if decryption fails.
     */
    fun getString(key: String, defaultValue: String?): String? {
        val encryptedValue = sharedPreferences.getString(key, null)
        return if (encryptedValue != null) {
            try {
                encryptionManager.decryptFromString(encryptedValue)
            } catch (e: Exception) {
                defaultValue
            }
        } else {
            defaultValue
        }
    }

    /**
     * Clears all values from this SharedPreferences.
     */
    fun clear() {
        sharedPreferences.edit().clear().apply()
    }
}
