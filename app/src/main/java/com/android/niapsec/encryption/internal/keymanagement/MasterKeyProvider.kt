package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator


/**
 * AEAD+AES256 Key Provider: Use User Preference to store the master key.
 * User can encode items with unlock device required flag even when the device is locked.
 * Note: The implementation uses Preference file, so it's not safety enough.
 */
class MasterKeyProvider(
    private val context: Context,
    private val masterKeyUri: String,
    _unlockedDeviceRequired: Boolean,
    private val keysetPrefName: String
) : KeyProvider {

    private val HARDWARE_KEYSET_NAME = "hardware_keyset"
    val unlockedDeviceRequired:Boolean = _unlockedDeviceRequired

    private val _cachedAead: Aead by lazy {
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, HARDWARE_KEYSET_NAME, keysetPrefName)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        keysetHandle.getPrimitive(RegistryConfiguration.get(),Aead::class.java)
    }

    init {
        AeadConfig.register()
        createMasterKeyIfNeeded()
        _cachedAead
    }
    override fun getUnlockDeviceRequired():Boolean
    {
        return unlockedDeviceRequired
    }

    private fun createMasterKeyIfNeeded() {
        val keyAlias = masterKeyUri.removePrefix("android-keystore://")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val specBuilder = KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
            if (unlockedDeviceRequired) {
                specBuilder.setUnlockedDeviceRequired(true)
            }
            keyGenerator.init(specBuilder.build())
            keyGenerator.generateKey()
        }
    }


    override fun getCachedAead(): Aead {
        if(unlockedDeviceRequired){
            return _cachedAead;
        } else {
            return getAead()
        }
    }
    override fun getAead(): Aead {
        // ALWAYS create a new manager to bypass Tink's in-memory caching.
        // This is essential for test isolation.
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, HARDWARE_KEYSET_NAME,keysetPrefName)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        return keysetHandle.getPrimitive(RegistryConfiguration.get(),Aead::class.java)
    }

    override fun destroy() {

        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val keyAlias = masterKeyUri.removePrefix("android-keystore://")

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }

        } catch (e: Exception) {
            Log.e("KeyStoreInspector", "Failed to list keys", e)
        }
        // Aggressive cleanup: delete the underlying files directly.
        val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")
        val hardwarePrefsFile = File(prefsDir, "$keysetPrefName.xml")
        if (hardwarePrefsFile.exists()) {
            hardwarePrefsFile.delete()
        }

        val keyAlias = masterKeyUri.removePrefix("android-keystore://")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }
}
