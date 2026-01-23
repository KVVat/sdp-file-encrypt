package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.google.crypto.tink.Aead
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * A KeyProvider that generates and stores an Elliptic Curve key pair for use with
 * ECIES (Elliptic Curve Integrated Encryption Scheme).
 *
 * This provider is designed for asymmetric encryption. The generated keyset is stored
 * in SharedPreferences, encrypted with a master key from the Android Keystore.
 *
 * Note: The default Tink template for ECIES uses the P256 curve.
 */
class P521KeyProvider(
    private val context: Context,
    private val masterKeyUri: String,
    _unlockedDeviceRequired: Boolean,
    private val keysetPrefName: String
) : KeyProvider {

    private val P521_KEYSET_NAME = "p521_keyset"
    val unlockedDeviceRequired: Boolean = _unlockedDeviceRequired

    private val _cachedAead: Aead by lazy {
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, P521_KEYSET_NAME, keysetPrefName)
            .withKeyTemplate(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        createAead(keysetHandle)
    }

    init {
        AeadConfig.register()
        HybridConfig.register()
        createMasterKeyIfNeeded()
        _cachedAead
    }

    override fun getUnlockDeviceRequired(): Boolean {
        return unlockedDeviceRequired
    }

    private fun createMasterKeyIfNeeded() {
        val keyAlias = masterKeyUri.removePrefix("android-keystore://")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val specBuilder = KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
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
        return _cachedAead
    }

    override fun getAead(): Aead {
        // ALWAYS create a new manager to bypass Tink's in-memory caching.
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, P521_KEYSET_NAME, keysetPrefName)
            .withKeyTemplate(KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle
        return createAead(keysetHandle)
    }

    private fun createAead(keysetHandle: KeysetHandle): Aead {
        val publicKeysetHandle = keysetHandle.publicKeysetHandle
        val hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt::class.java)
        val hybridDecrypt = keysetHandle.getPrimitive(HybridDecrypt::class.java)

        return object : Aead {
            override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
                return hybridEncrypt.encrypt(plaintext, associatedData)
            }

            override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
                return hybridDecrypt.decrypt(ciphertext, associatedData)
            }
        }
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
        val p521PrefsFile = File(prefsDir, "$P521_KEYSET_NAME.xml")
        if (p521PrefsFile.exists()) {
            p521PrefsFile.delete()
        }
    }
}
