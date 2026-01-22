package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
//import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProtection
//import androidx.compose.foundation.text2.input.delete
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.File
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * WARNING: INSECURE - FOR EDUCATIONAL PURPOSES ONLY.
 *
 * This KeyProvider demonstrates how to create and persist a purely software-based keyset
 * without the protection of the Android Keystore. The keyset is stored IN CLEARTEXT
 * in SharedPreferences, which is a major security risk.
 *
 * This version also incorrectly includes logic for creating a hardware-backed master key
 * that is never actually used to protect the software key, demonstrating a common
 * anti-pattern.
 */
class InsecureSoftwareKeyProvider(
    private val context: Context,
    private val prefName: String,
    private val masterKeyUri: String,
    private val unlockedDeviceRequired: Boolean
) : KeyProvider {
    init {
        AeadConfig.register()
        createMasterKeyIfNeeded()
    }
    override fun getUnlockDeviceRequired():Boolean
    {
        return unlockedDeviceRequired
    }
    private val SOFTWARE_KEYSET_NAME = "software_keyset"
    private fun createMasterKeyIfNeeded() {
        val keyAlias = masterKeyUri.removePrefix("android-keystore://")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(keyAlias)) {
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidOpenSSL")
            keyGenerator.init(256) // keysize
            val secretKey = keyGenerator.generateKey()

            val protectionParameter = KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)

            if (unlockedDeviceRequired) {
                protectionParameter.setUnlockedDeviceRequired(true)
            }
            //.setUnlockedDeviceRequired(true)
            //protectionParameter.build()
            keyStore.setEntry(
                keyAlias,
                KeyStore.SecretKeyEntry(secretKey),
                protectionParameter.build()
            )
            //KeyProtection.Builder( KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT))
            //keyGenerator.init(specBuilder.build())
            //keyGenerator.generateKey()
        }
    }

    override fun getCachedAead(): Aead {
        return getAead()
    }

    override fun getAead(): Aead {

        // ALWAYS create a new manager to bypass Tink's in-memory caching.
        // This is essential for test isolation.
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, SOFTWARE_KEYSET_NAME,prefName)
            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withMasterKeyUri(masterKeyUri)
            .build()
            .keysetHandle


        return keysetHandle.getPrimitive(RegistryConfiguration.get(),Aead::class.java)

        //return keysetHandle.getPrimitive(Aead::class.java)
        /*
        val sharedPreferences = context.getSharedPreferences(prefName, Context.MODE_PRIVATE)
        val serializedKeyset = sharedPreferences.getString("insecure_software_keyset", null)

        val keysetHandle: KeysetHandle = if (serializedKeyset == null) {
            // 1. Keyset doesn't exist, so we generate a new one in software.
            val newHandle = KeysetHandle.generateNew(KeyTemplates.get("AES256_GCM"))

            // 2. INSECURE: Write the new keyset to a byte array in cleartext.
            val baos = ByteArrayOutputStream()
            CleartextKeysetHandle.write(newHandle, BinaryKeysetWriter.withOutputStream(baos))
            val newSerializedKeyset = Base64.encodeToString(baos.toByteArray(), Base64.DEFAULT)

            // 3. INSECURE: Persist the cleartext keyset to SharedPreferences.
            sharedPreferences.edit().putString("insecure_software_keyset", newSerializedKeyset).commit()
            newHandle
        } else {
            // Keyset exists, so we read the cleartext data from SharedPreferences.
            val bytes = Base64.decode(serializedKeyset, Base64.DEFAULT)
            val bais = ByteArrayInputStream(bytes)
            CleartextKeysetHandle.read(BinaryKeysetReader.withInputStream(bais))
        }*/
        //return keysetHandle.getPrimitive(Aead::class.java)
    }

    /**
     * Deletes the insecure keyset from storage.
     */
    override fun destroy() {

        //Registry.
        // Aggressive cleanup: delete the underlying files directly to ensure no state pollution.
        val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")
        val prefsFile = File(prefsDir, "$prefName.xml")
        if (prefsFile.exists()) {
            prefsFile.delete()
        }

        // Also attempt to destroy the (unused) hardware key.
        val keyAlias = masterKeyUri.removePrefix("android-keystore://")
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }
}
