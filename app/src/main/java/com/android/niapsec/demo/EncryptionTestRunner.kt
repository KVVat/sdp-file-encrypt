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
package com.android.niapsec.demo

import android.content.Context
import android.util.Log
import com.android.niapsec.encryption.api.EncryptionManager
import java.io.File

data class TestResult(val testName: String, val passed: Boolean, val message: String)

class EncryptionTestRunner(private val context: Context) {

    companion object {
        const val ENCRYPTED_FILE_NAME = "test_file.txt"
        const val ORIGINAL_TEXT = "This is a secret message."
    }

    fun runFullTest(
        encryptionManager: EncryptionManager,
        testName: String,
        reverseEncryptionResult: Boolean = false,
        reverseDecryptionResult: Boolean = false
    ): List<TestResult> {
        Log.d(testName, "--- STARTING TEST (Reverse Encrypt: $reverseEncryptionResult, Reverse Decrypt: $reverseDecryptionResult) ---")
        val file = File(context.filesDir, "$testName-$ENCRYPTED_FILE_NAME")
        val results = mutableListOf<TestResult>()

        // Run Encryption Phase
        val encryptionResult = testEncryption(encryptionManager, file, testName, reverseEncryptionResult)
        results.add(encryptionResult)
        if (encryptionResult.passed) {
            Log.d(testName, "Encryption test phase PASSED.")
        } else {
            Log.e(testName, "Encryption test phase FAILED.")
        }

        // Run Decryption Phase
        val decryptionResult = testDecryption(encryptionManager, file, testName, reverseDecryptionResult)
        results.add(decryptionResult)
        if (decryptionResult.passed) {
            Log.d(testName, "Decryption test phase PASSED.")
        } else {
            Log.e(testName, "Decryption test phase FAILED.")
        }
        Log.d(testName, "--- TEST COMPLETE ---")
        return results
    }

    private fun testEncryption(encryptionManager: EncryptionManager, file: File, testName: String, reverseResult: Boolean): TestResult {
        return try {
            Log.d(testName, "Attempting encryption...")
            encryptionManager.encryptToFile(file).use { it.write(ORIGINAL_TEXT.toByteArray()) }
            val passed = !reverseResult
            val message = if (passed) "Encryption successful" else "Encryption expected to fail but succeeded"
            TestResult(testName, passed, message)
        } catch (e: Exception) {
            val passed = reverseResult
            val message = if (passed) "Encryption failed as expected" else "Encryption failed unexpectedly"
            Log.e(testName, message, e)
            TestResult(testName, passed, message)
        }
    }

    private fun testDecryption(encryptionManager: EncryptionManager, file: File, testName: String, reverseResult: Boolean): TestResult {
        return try {
            Log.d(testName, "Attempting decryption...")
            val decryptedText = encryptionManager.decryptFromFile(file).use { it.reader().readText() }
            if (ORIGINAL_TEXT == decryptedText) {
                val passed = !reverseResult
                val message = if (passed) "Decryption successful and content matches" else "Decryption expected to fail but succeeded"
                TestResult(testName, passed, message)
            } else {
                val passed = reverseResult
                val message = "Decryption succeeded but content MISMATCH"
                Log.e(testName, message)
                TestResult(testName, passed, message)
            }
        } catch (e: Exception) {
            val passed = reverseResult
            val message = if (passed) "Decryption failed as expected" else "Decryption failed unexpectedly"
            Log.e(testName, message, e)
            TestResult(testName, passed, message)
        }
    }
}