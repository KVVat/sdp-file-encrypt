package com.android.niapsec.demo

import android.content.Context
import android.util.Log
import com.android.niapsec.encryption.api.EncryptionManager
import java.io.File

class EncryptionTestRunner(private val context: Context) {

    companion object {
        private const val ENCRYPTED_FILE_NAME = "test_file.txt"
        private const val ORIGINAL_TEXT = "This is a secret message."
    }

    fun runFullTest(
        encryptionManager: EncryptionManager,
        testName: String,
        reverseEncryptionResult: Boolean = false,
        reverseDecryptionResult: Boolean = false
    ) {
        Log.d(testName, "--- STARTING TEST (Reverse Encrypt: $reverseEncryptionResult, Reverse Decrypt: $reverseDecryptionResult) ---")
        val file = File(context.filesDir, "$testName-$ENCRYPTED_FILE_NAME")

        // Run Encryption Phase
        val encryptionPassed = testEncryption(encryptionManager, file, testName, reverseEncryptionResult)
        if (encryptionPassed) {
            Log.d(testName, "Encryption test phase PASSED.")
        } else {
            Log.e(testName, "Encryption test phase FAILED.")
        }

        // Run Decryption Phase
        val decryptionPassed = testDecryption(encryptionManager, file, testName, reverseDecryptionResult)
        if (decryptionPassed) {
            Log.d(testName, "Decryption test phase PASSED.")
        } else {
            Log.e(testName, "Decryption test phase FAILED.")
        }
        Log.d(testName, "--- TEST COMPLETE ---")
    }

    private fun testEncryption(encryptionManager: EncryptionManager, file: File, testName: String, reverseResult: Boolean): Boolean {
        return try {
            Log.d(testName, "Attempting encryption...")
            encryptionManager.encryptToFile(file).use { it.write(ORIGINAL_TEXT.toByteArray()) }
            Log.d(testName, "File encrypted successfully.")
            !reverseResult // Success, return true unless reversed
        } catch (e: Exception) {
            Log.e(testName, "Encryption failed.", e)
            reverseResult // Failure, return true if reversed
        }
    }

    private fun testDecryption(encryptionManager: EncryptionManager, file: File, testName: String, reverseResult: Boolean): Boolean {
        return try {
            Log.d(testName, "Attempting decryption...")
            val decryptedText = encryptionManager.decryptFromFile(file).use { it.reader().readText() }
            if (ORIGINAL_TEXT == decryptedText) {
                Log.d(testName, "File decrypted successfully and content matches.")
                !reverseResult // Success
            } else {
                Log.e(testName, "Decryption succeeded but content MISMATCH.")
                reverseResult // Failure
            }
        } catch (e: Exception) {
            Log.e(testName, "Decryption failed.", e)
            reverseResult // Failure
        }
    }
}