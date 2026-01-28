package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.google.crypto.tink.Aead
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeyTemplate
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.proto.AesGcmKeyFormat
import com.google.crypto.tink.proto.EcPointFormat
import com.google.crypto.tink.proto.EciesAeadDemParams
import com.google.crypto.tink.proto.EciesAeadHkdfKeyFormat
import com.google.crypto.tink.proto.EciesAeadHkdfParams
import com.google.crypto.tink.proto.EciesHkdfKemParams
import com.google.crypto.tink.proto.EllipticCurveType
import com.google.crypto.tink.proto.HashType
import java.security.KeyStore
import javax.crypto.KeyGenerator

class HybridKeyProvider(
    private val context: Context,
    private val masterKeyUri: String,
    _unlockedDeviceRequired: Boolean,
    private val keysetPrefName: String
) : KeyProvider {

    companion object {
        val P521_AES256_GCM_TEMPLATE: KeyTemplate by lazy {
            val demAeadKeyFormat = AesGcmKeyFormat.newBuilder().setKeySize(32).build()
            val demKeyTemplate = com.google.crypto.tink.proto.KeyTemplate.newBuilder()
                .setValue(demAeadKeyFormat.toByteString())
                .setTypeUrl("type.googleapis.com/google.crypto.tink.AesGcmKey")
                .setOutputPrefixType(com.google.crypto.tink.proto.OutputPrefixType.TINK)
                .build()
            val demParams = EciesAeadDemParams.newBuilder().setAeadDem(demKeyTemplate).build()
            val kemParams = EciesHkdfKemParams.newBuilder()
                .setCurveType(EllipticCurveType.NIST_P521)
                .setHkdfHashType(HashType.SHA256)
                .build()
            val eciesParams = EciesAeadHkdfParams.newBuilder()
                .setKemParams(kemParams)
                .setDemParams(demParams)
                .setEcPointFormat(EcPointFormat.UNCOMPRESSED)
                .build()
            val keyFormat = EciesAeadHkdfKeyFormat.newBuilder()
                .setParams(eciesParams)
                .build()
            KeyTemplate.create(
                "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey",
                keyFormat.toByteString().toByteArray(),
                KeyTemplate.OutputPrefixType.TINK
            )
        }
    }

    private val HYBRID_KEYSET_NAME = "hybrid_keyset"
    val unlockedDeviceRequired: Boolean = _unlockedDeviceRequired

    private val _cachedAead: Aead by lazy {
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, HYBRID_KEYSET_NAME, keysetPrefName)
            .withKeyTemplate(P521_AES256_GCM_TEMPLATE)
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
        val keysetHandle = AndroidKeysetManager.Builder()
            .withSharedPref(context, HYBRID_KEYSET_NAME, keysetPrefName)
            .withKeyTemplate(P521_AES256_GCM_TEMPLATE)
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
        context.getSharedPreferences(keysetPrefName, Context.MODE_PRIVATE).edit().clear().commit()

        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val keyAlias = masterKeyUri.removePrefix("android-keystore://")
            if (keyStore.containsAlias(keyAlias)) {
                keyStore.deleteEntry(keyAlias)
            }
        } catch (e: Exception) {
            Log.e("HybridKeyProvider", "Failed to destroy master key", e)
        }
    }
}
