package com.android.niapsec.encryption.internal.keymanagement

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.google.crypto.tink.Aead
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import androidx.core.content.edit
import com.google.crypto.tink.subtle.Hkdf

/**
 * A KeyProvider that implements a hybrid encryption scheme (ECDH + HKDF + AES-GCM) using raw JCA.
 * This approach avoids exposing sensitive key material to memory buffers managed by third-party libraries
 * and ensures that intermediate keys are zeroed out after use.
 *
 * It is designed to be compatible with the Tink `Aead` interface for seamless integration.
 */
class RawHybridKeyProvider(
    private val context: Context,
    private val masterKeyUri: String,
    _unlockedDeviceRequired: Boolean,
    private val keysetPrefName: String
) : KeyProvider {

    private val masterKeyAlias = masterKeyUri.removePrefix("android-keystore://")
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private val prefs = context.getSharedPreferences(keysetPrefName, Context.MODE_PRIVATE)
    val unlockedDeviceRequired: Boolean = _unlockedDeviceRequired

    // Private constants for cryptographic operations
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

        private const val HKDF_DIGEST = "SHA-256"
    }

    init {
        // Generate the master key pair if it doesn't exist.
        generateAndStoreKeyPairIfNeeded()
    }

    private fun generateAndStoreKeyPairIfNeeded() {
        if (!keyStore.containsAlias(masterKeyAlias)) {
            val kpg = KeyPairGenerator.getInstance(EC_KEY_ALGORITHM, ANDROID_KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                masterKeyAlias,
                KeyProperties.PURPOSE_AGREE_KEY // For ECDH
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUnlockedDeviceRequired(unlockedDeviceRequired)
                .build()

            kpg.initialize(spec)
            val keyPair = kpg.generateKeyPair()

            // Save the public key to SharedPreferences for use during encryption.
            val encodedKey = Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP)
            prefs.edit { putString(KEY_PUBLIC_KEY_PREF, encodedKey) }
        }
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

    private val rawHybridAead: Aead = object : Aead {
        override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
            val recipientPubKey = loadRecipientPublicKey()

            // Temporary byte arrays for sensitive key material. Will be zeroed out in finally.
            val dekBytes = ByteArray(DEK_SIZE_BITS / 8)
            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null

            try {
                // 1. Generate a fresh Data Encryption Key (DEK) for each encryption.
                SecureRandom().nextBytes(dekBytes)
                val dekSpec = SecretKeySpec(dekBytes, DEK_ALGORITHM)

                // 2. Encrypt the actual data with the DEK using AES-GCM.
                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                dataCipher.init(Cipher.ENCRYPT_MODE, dekSpec)
                val encryptedContent = dataCipher.doFinal(plaintext)
                val dataIv = dataCipher.iv

                // 3. Generate an ephemeral key pair for ECDH key agreement.
                val ephemeralKpg = KeyPairGenerator.getInstance(EC_KEY_ALGORITHM).apply { initialize(256) }
                val ephemeralKeyPair = ephemeralKpg.generateKeyPair()

                // 4. Perform ECDH to establish a shared secret.
                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(ephemeralKeyPair.private)
                keyAgreement.doPhase(recipientPubKey, true)
                sharedSecret = keyAgreement.generateSecret()

                // 5. Derive a Key Encryption Key (KEK) from the shared secret using HKDF.
                kekBytes = hkdfDerive(ikm=sharedSecret, salt=masterKeyAlias.toByteArray(Charsets.UTF_8),info=ephemeralKeyPair.public.encoded)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)

                // 6. Wrap (encrypt) the DEK with the KEK.
                val wrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                wrapCipher.init(Cipher.ENCRYPT_MODE, kekSpec)
                val wrappedDek = wrapCipher.doFinal(dekBytes)
                val wrapIv = wrapCipher.iv

                // 7. Serialize all components into a single byte array for storage/transmission.
                return serializeEncryptedPackage(
                    ephemeralPublicKeyBytes = ephemeralKeyPair.public.encoded,
                    wrappedDek = wrappedDek,
                    wrapIv = wrapIv,
                    encryptedContent = encryptedContent,
                    dataIv = dataIv
                )
            } finally {
                // Securely clear sensitive key material from memory.
                dekBytes.fill(0)
                sharedSecret?.fill(0)
                kekBytes?.fill(0)
            }
        }

        override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
            // 1. Deserialize the ciphertext package into its components.
            val pkg = deserializeEncryptedPackage(ciphertext)
            val recipientPrivateKey = loadRecipientPrivateKey()

            // Reconstruct the ephemeral public key from its byte representation.
            val ephemeralPubKeySpec = X509EncodedKeySpec(pkg.ephemeralPublicKeyBytes)
            val ephemeralPublicKey = KeyFactory.getInstance(EC_KEY_ALGORITHM).generatePublic(ephemeralPubKeySpec)

            // Temporary byte arrays for sensitive key material. Will be zeroed out in finally.
            var sharedSecret: ByteArray? = null
            var kekBytes: ByteArray? = null
            var dekBytes: ByteArray? = null

            try {
                // 2. Perform ECDH to re-establish the same shared secret.
                val keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM)
                keyAgreement.init(recipientPrivateKey)
                keyAgreement.doPhase(ephemeralPublicKey, true)
                sharedSecret = keyAgreement.generateSecret()

                // 3. Derive the KEK from the shared secret using HKDF.
                kekBytes = hkdfDerive(ikm=sharedSecret, salt=masterKeyAlias.toByteArray(Charsets.UTF_8),info=pkg.ephemeralPublicKeyBytes)
                val kekSpec = SecretKeySpec(kekBytes, DEK_ALGORITHM)

                // 4. Unwrap (decrypt) the DEK with the KEK.
                val unwrapCipher = Cipher.getInstance(DEK_WRAPPING_CIPHER)
                val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, pkg.wrapIv)
                unwrapCipher.init(Cipher.DECRYPT_MODE, kekSpec, gcmSpec)
                dekBytes = unwrapCipher.doFinal(pkg.wrappedDek)

                // 5. Decrypt the actual data with the DEK.
                val dataCipher = Cipher.getInstance(DATA_CIPHER)
                val dekSpec = SecretKeySpec(dekBytes, DEK_ALGORITHM)
                val dataGcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, pkg.dataIv)
                dataCipher.init(Cipher.DECRYPT_MODE, dekSpec, dataGcmSpec)

                return dataCipher.doFinal(pkg.encryptedContent)
            } finally {
                // Securely clear sensitive key material from memory.
                sharedSecret?.fill(0)
                kekBytes?.fill(0)
                dekBytes?.fill(0)
            }
        }
    }

    // A simple HKDF implementation using SHA-256.( not depend on tink)
    /*
    private fun hkdfDerive(secret: ByteArray, info: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(HKDF_DIGEST)
        md.update(info)
        return md.digest(secret) // Returns 32 bytes for AES-256
    }
    */
    /**
     * Derives a key from the input keying material (ikm) using Tink's HKDF implementation.
     * This is more secure and standard-compliant than a manual implementation.
     *
     * @param ikm The input keying material, typically a high-entropy secret.
     * @param salt A non-secret salt. Using the unique keyAlias is a good practice.
     * @param info Context-specific information to bind the key to its purpose.
     * @return A derived 32-byte key suitable for AES-256.
     */
    private fun hkdfDerive(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        // Tink's secure and standard-compliant HKDF implementation (RFC 5869)
        return Hkdf.computeHkdf(
            "HmacSha256", // The MAC algorithm for the HKDF extraction phase. SHA-256 is standard.
            ikm,          // Input Keying Material: The secret to derive from.
            salt,         // Salt: A non-secret random value. Helps protect against pre-computation attacks.
            info,         // Info: Context string. Ensures the derived key is unique to this purpose.
            32            // Size in Bytes: 32 bytes for an AES-256 key.
        )
    }


    override fun getAead(): Aead = rawHybridAead

    override fun getUnlockDeviceRequired(): Boolean = unlockedDeviceRequired

    override fun destroy() {
        try {
            if (keyStore.containsAlias(masterKeyAlias)) {
                keyStore.deleteEntry(masterKeyAlias)
            }
            prefs.edit().remove(KEY_PUBLIC_KEY_PREF).apply()
        } catch (e: Exception) {
            // Log error, but don't crash the app.
        }
    }
}

// A simple data class to hold the components of the encrypted data.
private data class EncryptedPackage(
    val ephemeralPublicKeyBytes: ByteArray,
    val wrappedDek: ByteArray,
    val wrapIv: ByteArray,
    val encryptedContent: ByteArray,
    val dataIv: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedPackage

        if (!ephemeralPublicKeyBytes.contentEquals(other.ephemeralPublicKeyBytes)) return false
        if (!wrappedDek.contentEquals(other.wrappedDek)) return false
        if (!wrapIv.contentEquals(other.wrapIv)) return false
        if (!encryptedContent.contentEquals(other.encryptedContent)) return false
        if (!dataIv.contentEquals(other.dataIv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ephemeralPublicKeyBytes.contentHashCode()
        result = 31 * result + wrappedDek.contentHashCode()
        result = 31 * result + wrapIv.contentHashCode()
        result = 31 * result + encryptedContent.contentHashCode()
        result = 31 * result + dataIv.contentHashCode()
        return result
    }
}

/**
 * Serializes an EncryptedPackage into a single ByteArray.
 * Format: [ephKey_len][ephKey][wrapDek_len][wrapDek][wrapIv_len][wrapIv][dataIv_len][dataIv][content]
 */
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

/**
 * Deserializes a ByteArray back into an EncryptedPackage.
 */
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
