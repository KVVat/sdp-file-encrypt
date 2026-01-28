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
import java.security.KeyStore
import javax.crypto.KeyGenerator

class SecureKeyProvider(
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
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, HARDWARE_KEYSET_NAME,keysetPrefName)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        return keysetHandle.getPrimitive(RegistryConfiguration.get(),Aead::class.java)
    }

    override fun destroy() {
        context.getSharedPreferences(keysetPrefName, Context.MODE_PRIVATE).edit().clear().commit()
        context.getSharedPreferences(HARDWARE_KEYSET_NAME, Context.MODE_PRIVATE).edit().clear().commit()

        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val keyAlias = masterKeyUri.removePrefix("android-keystore://")

            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
        } catch (e: Exception) {
            Log.e("SecureKeyProvider", "Failed to destroy master key", e)
        }
    }
}
