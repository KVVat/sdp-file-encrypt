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
    fun testInsecureProvider_encryptAndDecrypt_works() {
        val encryptionManager = createManager(KeyProviderType.INSECURE_SOFTWARE_ONLY)
        val testFile = getTestFile("insecure_provider_test.txt")
        val originalContent = "This is a secret message for the insecure provider."

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

    @Test
    fun testInsecureProvider_isAvailableWhenDeviceIsLocked() {
        val encryptionManager = createManager(KeyProviderType.INSECURE_SOFTWARE_ONLY)
        val testFile = getTestFile("insecure_provider_locked_test.txt")
        val originalContent = "This should be readable when locked."

        assumeTrue("This test requires the device to be locked.", keyguardManager.isDeviceLocked)
        
        try {
            encryptionManager.encryptToFile(testFile).use { it.write(originalContent.toByteArray()) }
            val decryptedContent = encryptionManager.decryptFromFile(testFile).use { it.reader().readText() }
            assertEquals(originalContent, decryptedContent)
        } catch (e: GeneralSecurityException) {
            fail("Encryption/decryption with the insecure provider failed unexpectedly while device is locked: ${e.message}")
        }
    }
}
