package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.core.content.edit
import com.google.crypto.tink.Aead
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.subtle.Hkdf
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.channels.ReadableByteChannel
import java.nio.channels.SeekableByteChannel
import java.nio.channels.WritableByteChannel
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A KeyProvider that implements a hybrid encryption scheme (ECDH + HKDF + AES-GCM) using raw JCA.
 * Compatible with Tink's Aead and StreamingAead interfaces.
 */
class RawHybridKeyProvider(
    private val context: Context,
    private val masterKeyUri: String,
    _unlockedDeviceRequired: Boolean,
    private val keysetPrefName: String
) : KeyProvider {



    // ... (既存の定数やinitブロック、generateAndStoreKeyPairIfNeeded等は変更なし) ...
    private val masterKeyAlias = masterKeyUri.removePrefix("android-keystore://")
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val unlockedDeviceRequired: Boolean = _unlockedDeviceRequired

    private val storageContext: Context = if (!unlockedDeviceRequired) {
        context.createDeviceProtectedStorageContext()
    } else {
        context
    }

    private val prefs = storageContext.getSharedPreferences(keysetPrefName, Context.MODE_PRIVATE)

    private companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_PUBLIC_KEY_PREF = "master_public_key"
        private const val EC_KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_EC
        private const val KEY_AGREEMENT_ALGORITHM = "ECDH"
        private const val DEK_ALGORITHM = "AES"
        private const val DEK_WRAPPING_CIPHER = "AES/GCM/NoPadding"
        private const val DEK_SIZE_BITS = 256
        private const val DATA_CIPHER = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH_BITS = 128
    }

    init {
        generateAndStoreKeyPairIfNeeded()
    }

    // ... (generateAndStoreKeyPairIfNeeded, loadRecipientPublicKey, loadRecipientPrivateKey, hkdfDeriveはそのまま) ...

    private fun generateAndStoreKeyPairIfNeeded() {

        if (keyStore.containsAlias(masterKeyAlias)) {
            if (!prefs.contains(KEY_PUBLIC_KEY_PREF)) {
                try {
                    val entry = keyStore.getEntry(masterKeyAlias, null) as? KeyStore.PrivateKeyEntry
                    entry?.certificate?.publicKey?.let { publicKey ->
                        savePublicKey(publicKey)
                    }
                } catch (e: Exception) {
                    // Key might be broken!, only record the log in this time.
                }
            }
        } else {
            // 新規生成
            val kpg = KeyPairGenerator.getInstance(EC_KEY_ALGORITHM, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                masterKeyAlias,
                KeyProperties.PURPOSE_AGREE_KEY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUnlockedDeviceRequired(unlockedDeviceRequired) // ここで false が渡されれば BFU 対応キーとなる
                .build()

            kpg.initialize(spec)
            val keyPair = kpg.generateKeyPair()

            savePublicKey(keyPair.public)
        }
    }

    private fun savePublicKey(publicKey: PublicKey) {
        val encodedKey = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
        prefs.edit { putString(KEY_PUBLIC_KEY_PREF, encodedKey) }
    }

    private fun loadRecipientPublicKey(): PublicKey {
        val encodedKey = prefs.getString(KEY_PUBLIC_KEY_PREF, null)
            ?: throw GeneralSecurityException("Master public key not found in SharedPreferences.")
        val bytes = Base64.decode(encodedKey, Base64.NO_WRAP)
        val spec = X509EncodedKeySpec(bytes)
        return KeyFactory.getInstance(EC_KEY_ALGORITHM).generatePublic(spec)
    }

    private fun loadRecipientPrivateKey(): PrivateKey {
        val entry = keyStore.getEntry(masterKeyAlias, null)
            ?: throw GeneralSecurityException("Master key alias not found in Keystore: $masterKeyAlias")
        if (entry !is KeyStore.PrivateKeyEntry) {
            throw GeneralSecurityException("Keystore entry is not a private key: $masterKeyAlias")
        }
        return entry.privateKey
    }

    private fun hkdfDerive(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        return Hkdf.computeHkdf("HmacSha256", ikm, salt, info, 32)
    }

    // --- AEAD Implementation (In-Memory) ---
    private val rawHybridAead: Aead = object : Aead {
        override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
            // (既存の実装のまま変更なし)
            val recipientPubKey = loadRecipientPublicKey()
            val dekBytes = ByteArray(DEK_SIZE_BITS / 8)
            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null
            try {
                SecureRandom().nextBytes(dekBytes)
                val dekSpec = SecretKeySpec(dekBytes, DEK_ALGORITHM)
                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                dataCipher.init(Cipher.ENCRYPT_MODE, dekSpec)
                dataCipher.updateAAD(associatedData)
                val encryptedContent = dataCipher.doFinal(plaintext)
                val dataIv = dataCipher.iv
                val ephemeralKpg = KeyPairGenerator.getInstance(EC_KEY_ALGORITHM).apply { initialize(256) }
                val ephemeralKeyPair = ephemeralKpg.generateKeyPair()
                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(ephemeralKeyPair.private)
                keyAgreement.doPhase(recipientPubKey, true)
                sharedSecret = keyAgreement.generateSecret()
                kekBytes = hkdfDerive(sharedSecret, masterKeyAlias.toByteArray(Charsets.UTF_8), ephemeralKeyPair.public.encoded)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)
                val wrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                wrapCipher.init(Cipher.ENCRYPT_MODE, kekSpec)
                val wrappedDek = wrapCipher.doFinal(dekBytes)
                val wrapIv = wrapCipher.iv
                return serializeEncryptedPackage(ephemeralKeyPair.public.encoded, wrappedDek, wrapIv, encryptedContent, dataIv)
            } finally {
                dekBytes.fill(0); sharedSecret?.fill(0); kekBytes?.fill(0)
            }
        }

        override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
            // (既存の実装のまま変更なし)
            val pkg = deserializeEncryptedPackage(ciphertext)
            val recipientPrivateKey = loadRecipientPrivateKey()
            val ephemeralPubKeySpec = X509EncodedKeySpec(pkg.ephemeralPublicKeyBytes)
            val ephemeralPublicKey = KeyFactory.getInstance(EC_KEY_ALGORITHM).generatePublic(ephemeralPubKeySpec)
            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null
            var dekBytes: ByteArray? = null
            try {
                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(recipientPrivateKey)
                keyAgreement.doPhase(ephemeralPublicKey, true)
                sharedSecret = keyAgreement.generateSecret()
                kekBytes = hkdfDerive(sharedSecret, masterKeyAlias.toByteArray(Charsets.UTF_8), pkg.ephemeralPublicKeyBytes)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)
                val unwrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                unwrapCipher.init(Cipher.DECRYPT_MODE, kekSpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, pkg.wrapIv))
                dekBytes = unwrapCipher.doFinal(pkg.wrappedDek)
                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                dataCipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dekBytes, DEK_ALGORITHM), GCMParameterSpec(GCM_TAG_LENGTH_BITS, pkg.dataIv))
                dataCipher.updateAAD(associatedData)
                return dataCipher.doFinal(pkg.encryptedContent)
            } finally {
                sharedSecret?.fill(0); kekBytes?.fill(0); dekBytes?.fill(0)
            }
        }
    }

    // --- StreamingAead Implementation ---
    private val rawHybridStreamingAead: StreamingAead = object : StreamingAead {
        override fun newEncryptingChannel(
            ciphertextDestination: WritableByteChannel?,
            associatedData: ByteArray?
        ): WritableByteChannel? {
            TODO("Not yet implemented")
        }

        override fun newSeekableDecryptingChannel(
            ciphertextSource: SeekableByteChannel?,
            associatedData: ByteArray?
        ): SeekableByteChannel? {
            TODO("Not yet implemented")
        }

        override fun newDecryptingChannel(
            ciphertextSource: ReadableByteChannel?,
            associatedData: ByteArray?
        ): ReadableByteChannel? {
            TODO("Not yet implemented")
        }

        override fun newEncryptingStream(ciphertext: OutputStream, associatedData: ByteArray): OutputStream {
            val recipientPubKey = loadRecipientPublicKey()
            val dekBytes = ByteArray(DEK_SIZE_BITS / 8)
            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null

            try {
                SecureRandom().nextBytes(dekBytes)
                val dekSpec = SecretKeySpec(dekBytes, DEK_ALGORITHM)

                val ephemeralKpg = KeyPairGenerator.getInstance(EC_KEY_ALGORITHM).apply { initialize(256) }
                val ephemeralKeyPair = ephemeralKpg.generateKeyPair()

                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(ephemeralKeyPair.private)
                keyAgreement.doPhase(recipientPubKey, true)
                sharedSecret = keyAgreement.generateSecret()

                kekBytes = hkdfDerive(sharedSecret, masterKeyAlias.toByteArray(Charsets.UTF_8), ephemeralKeyPair.public.encoded)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)

                val wrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                wrapCipher.init(Cipher.ENCRYPT_MODE, kekSpec)
                val wrappedDek = wrapCipher.doFinal(dekBytes)
                val wrapIv = wrapCipher.iv

                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                dataCipher.init(Cipher.ENCRYPT_MODE, dekSpec)
                dataCipher.updateAAD(associatedData)
                val dataIv = dataCipher.iv

                // Write Header directly to the output stream
                val dos = DataOutputStream(ciphertext)
                val ephKeyBytes = ephemeralKeyPair.public.encoded
                dos.writeInt(ephKeyBytes.size)
                dos.write(ephKeyBytes)
                dos.writeInt(wrappedDek.size)
                dos.write(wrappedDek)
                dos.writeInt(wrapIv.size)
                dos.write(wrapIv)
                dos.writeInt(dataIv.size)
                dos.write(dataIv)
                dos.flush()

                return CipherOutputStream(ciphertext, dataCipher)
            } finally {
                dekBytes.fill(0); sharedSecret?.fill(0); kekBytes?.fill(0)
            }
        }

        override fun newDecryptingStream(ciphertext: InputStream, associatedData: ByteArray): InputStream {
            val recipientPrivateKey = loadRecipientPrivateKey()
            val dis = DataInputStream(ciphertext)

            // Read Header
            val ephKeyLen = dis.readInt()
            val ephKeyBytes = ByteArray(ephKeyLen).apply { dis.readFully(this) }
            val ephemeralPublicKey = KeyFactory.getInstance(EC_KEY_ALGORITHM).generatePublic(X509EncodedKeySpec(ephKeyBytes))

            val wrapDekLen = dis.readInt()
            val wrappedDek = ByteArray(wrapDekLen).apply { dis.readFully(this) }

            val wrapIvLen = dis.readInt()
            val wrapIv = ByteArray(wrapIvLen).apply { dis.readFully(this) }

            val dataIvLen = dis.readInt()
            val dataIv = ByteArray(dataIvLen).apply { dis.readFully(this) }

            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null
            var dekBytes: ByteArray? = null

            try {
                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(recipientPrivateKey)
                keyAgreement.doPhase(ephemeralPublicKey, true)
                sharedSecret = keyAgreement.generateSecret()

                kekBytes = hkdfDerive(sharedSecret, masterKeyAlias.toByteArray(Charsets.UTF_8), ephKeyBytes)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)

                val unwrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                unwrapCipher.init(Cipher.DECRYPT_MODE, kekSpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, wrapIv))
                dekBytes = unwrapCipher.doFinal(wrappedDek)

                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                val dekSpec = SecretKeySpec(dekBytes, DEK_ALGORITHM)
                dataCipher.init(Cipher.DECRYPT_MODE, dekSpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, dataIv))
                dataCipher.updateAAD(associatedData)

                return CipherInputStream(ciphertext, dataCipher)
            } finally {
                sharedSecret?.fill(0); kekBytes?.fill(0); dekBytes?.fill(0)
            }
        }
    }

    override fun getAead(): Aead = rawHybridAead
    override fun getStreamingAead(): StreamingAead = rawHybridStreamingAead
    override fun getUnlockDeviceRequired(): Boolean = unlockedDeviceRequired

    override fun destroy() {
        try {
            if (keyStore.containsAlias(masterKeyAlias)) {
                keyStore.deleteEntry(masterKeyAlias)
            }
            prefs.edit().remove(KEY_PUBLIC_KEY_PREF).apply()
        } catch (e: Exception) { }
    }
}

// 既存の EncryptedPackage 関連のヘルパー関数とデータクラスはそのまま維持（Aead実装で使用するため）
private data class EncryptedPackage(
    val ephemeralPublicKeyBytes: ByteArray,
    val wrappedDek: ByteArray,
    val wrapIv: ByteArray,
    val encryptedContent: ByteArray,
    val dataIv: ByteArray
)

private fun serializeEncryptedPackage(ephemeralPublicKeyBytes: ByteArray, wrappedDek: ByteArray, wrapIv: ByteArray, encryptedContent: ByteArray, dataIv: ByteArray): ByteArray {
    val bos = ByteArrayOutputStream()
    DataOutputStream(bos).use {
        it.writeInt(ephemeralPublicKeyBytes.size)
        it.write(ephemeralPublicKeyBytes)
        it.writeInt(wrappedDek.size)
        it.write(wrappedDek)
        it.writeInt(wrapIv.size)
        it.write(wrapIv)
        it.writeInt(dataIv.size)
        it.write(dataIv)
        it.write(encryptedContent)
    }
    return bos.toByteArray()
}

private fun deserializeEncryptedPackage(ciphertext: ByteArray): EncryptedPackage {
    val buffer = ByteBuffer.wrap(ciphertext)
    val ephKeySize = buffer.int
    val ephKey = ByteArray(ephKeySize).apply { buffer.get(this) }
    val wrapDekSize = buffer.int
    val wrapDek = ByteArray(wrapDekSize).apply { buffer.get(this) }
    val wrapIvSize = buffer.int
    val wrapIv = ByteArray(wrapIvSize).apply { buffer.get(this) }
    val dataIvSize = buffer.int
    val dataIv = ByteArray(dataIvSize).apply { buffer.get(this) }
    val content = ByteArray(buffer.remaining()).apply { buffer.get(this) }
    return EncryptedPackage(ephKey, wrapDek, wrapIv, content, dataIv)
}