package com.android.niapsec

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.android.niapsec.demo.EncryptedSharedPreferences
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class EncryptedSharedPreferencesTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val managersToDestroy = mutableListOf<EncryptionManager>()

    @Before
    @After
    fun cleanup() {
        managersToDestroy.forEach { it.destroy() }
        managersToDestroy.clear()
    }

    private fun createManager(providerType: KeyProviderType): EncryptionManager {
        val masterKeyUri = "android-keystore://test_prefs_key_${UUID.randomUUID()}"
        val manager = EncryptionManager(context, masterKeyUri, providerType)
        managersToDestroy.add(manager)
        return manager
    }

    @Test
    fun testSecureProvider_e2e() {
        val manager = createManager(KeyProviderType.SECURE)
        val prefs = EncryptedSharedPreferences(context, "test_secure_prefs", manager)
        runStandardTests(prefs)
    }

    private fun runStandardTests(prefs: EncryptedSharedPreferences) {
        // 1. Test basic put and get
        val key1 = "myKey1"
        val value1 = "my secret value"
        prefs.putString(key1, value1)
        assertEquals(value1, prefs.getString(key1, null))

        // 2. Test getting a non-existent key
        assertNull(prefs.getString("non_existent_key", null))
        assertEquals("default", prefs.getString("non_existent_key", "default"))

        // 3. Test overwriting a key
        val newValue1 = "a new secret"
        prefs.putString(key1, newValue1)
        assertEquals(newValue1, prefs.getString(key1, null))

        // 4. Test clearing the preferences
        prefs.clear()
        assertNull(prefs.getString(key1, null))
    }
}
