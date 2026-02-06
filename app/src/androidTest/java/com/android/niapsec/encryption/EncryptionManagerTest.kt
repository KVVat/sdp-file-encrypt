/*
* Copyright (C) 2026 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package com.android.niapsec.encryption

import android.app.KeyguardManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.GeneralSecurityException
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class EncryptionManagerTest {

    private lateinit var context: Context
    private lateinit var keyguardManager: KeyguardManager
    private val managersToDestroy = mutableListOf<EncryptionManager>()
    private val filesToClean = mutableListOf<File>()

    @Before
    fun setup() {
        context = InstrumentationRegistry.getInstrumentation().targetContext
        keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    }

    @After
    fun tearDown() {
        managersToDestroy.forEach { it.destroy() }
        managersToDestroy.clear()

        filesToClean.forEach { if (it.exists()) it.delete() }
        filesToClean.clear()
    }

    private fun createManager(providerType: KeyProviderType, unlockedDeviceRequired: Boolean = false): EncryptionManager {
        val masterKeyUri = "android-keystore://test_key_${UUID.randomUUID()}"
        val manager = EncryptionManager(context, masterKeyUri, providerType, unlockedDeviceRequired)
        managersToDestroy.add(manager)
        return manager
    }

    private fun getTestFile(fileName: String): File {
        val file = File(context.cacheDir, fileName)
        filesToClean.add(file)
        return file
    }

    // --- Existing SECURE Provider Tests ---

    @Test
    fun testSecureProvider_encryptAndDecrypt_works() {
        val encryptionManager = createManager(KeyProviderType.SECURE)
        val testFile = getTestFile("secure_provider_test.txt")
        val originalContent = "This is a secret message for the secure provider."

        encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
        val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }

        assertEquals(originalContent, decryptedContent)
    }

    @Test
    fun testSecureProvider_isUnavailableWhenDeviceIsLocked() {
        val encryptionManager = createManager(KeyProviderType.SECURE, unlockedDeviceRequired = true)
        val testFile = getTestFile("secure_provider_locked_test.txt")
        val originalContent = "This should not be readable when locked."

        if (!keyguardManager.isDeviceLocked) {
            try {
                encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
            } catch (e: GeneralSecurityException) {
                fail("Encryption with a secure key failed unexpectedly while device is unlocked: ${e.message}")
            }
        }

        assumeTrue("File for decryption does not exist. Run the test while unlocked first.", testFile.exists())
        assumeTrue("This part of the test requires the device to be locked.", keyguardManager.isDeviceLocked)

        try {
            encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }
            fail("Expected a GeneralSecurityException during decryption because the device is locked, but none was thrown.")
        } catch (e: GeneralSecurityException) {
            val message = e.message ?: ""
            assertTrue("Exception should indicate a device lock issue.", message.contains("unusable") || message.contains("Device locked"))
        }
    }

    // --- New Tests for Other Providers ---

    @Test
    fun testRawHybridProvider_encryptAndDecrypt_works() {
        // This provider uses the new StreamingAead implementation
        val encryptionManager = createManager(KeyProviderType.RAW_HYBRID)
        val testFile = getTestFile("raw_hybrid_test.txt")
        val originalContent = "Content encrypted via RawHybridKeyProvider (Streaming supported)."

        encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
        val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }

        assertEquals(originalContent, decryptedContent)
    }

    @Test
    fun testRawHybridProvider_largeData_works() {
        // Validates streaming implementation with larger data (e.g., 100KB)
        val encryptionManager = createManager(KeyProviderType.RAW_HYBRID)
        val testFile = getTestFile("raw_hybrid_large_test.dat")

        val sb = StringBuilder()
        repeat(1000) { sb.append("Line $it: This is a test line to generate some volume of data.\n") }
        val originalContent = sb.toString()

        encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
        val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }

        assertEquals("Decrypted content length mismatch", originalContent.length, decryptedContent.length)
        assertEquals("Decrypted content mismatch", originalContent, decryptedContent)
    }

    @Test
    fun testRawProvider_encryptAndDecrypt_works() {
        // Validates fallback to in-memory processing for non-streaming providers
        val encryptionManager = createManager(KeyProviderType.RAW)
        val testFile = getTestFile("raw_provider_test.txt")
        val originalContent = "Simple content for Raw Provider"

        encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
        val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }

        assertEquals(originalContent, decryptedContent)
    }

    @Test
    fun testHybridProvider_encryptAndDecrypt_works() {
        // Validates fallback to in-memory processing for non-streaming providers
        val encryptionManager = createManager(KeyProviderType.HYBRID)
        val testFile = getTestFile("hybrid_provider_test.txt")
        val originalContent = "Simple content for Hybrid Provider"

        encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
        val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }

        assertEquals(originalContent, decryptedContent)
    }

    // --- String Encryption Tests ---

    @Test
    fun testStringEncryption_works_secure() {
        val encryptionManager = createManager(KeyProviderType.SECURE)
        val originalText = "Hello World! String encryption test."

        val ciphertext = encryptionManager.encryptToString(originalText)
        val decryptedText = encryptionManager.decryptFromString(ciphertext)

        assertEquals(originalText, decryptedText)
    }

    @Test
    fun testStringEncryption_works_rawHybrid() {
        val encryptionManager = createManager(KeyProviderType.RAW_HYBRID)
        val originalText = "Hello World! String encryption test with RawHybrid."

        val ciphertext = encryptionManager.encryptToString(originalText)
        val decryptedText = encryptionManager.decryptFromString(ciphertext)

        assertEquals(originalText, decryptedText)
    }
}