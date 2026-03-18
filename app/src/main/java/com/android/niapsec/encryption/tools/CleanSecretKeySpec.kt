package com.android.niapsec.encryption.tools

import java.security.spec.KeySpec
import javax.crypto.SecretKey

/**
 * Custom SecretKeySpec class that implements the Destroyable interface.
 */
class CleanSecretKeySpec(
    key: ByteArray,
    private val algorithm: String
) : KeySpec, SecretKey{

    private val keyMaterial: ByteArray = key.clone()
    private var isDestroyedFlag: Boolean = false

    override fun getAlgorithm(): String = algorithm

    override fun getFormat(): String = "RAW"

    override fun getEncoded(): ByteArray? {
        if (isDestroyedFlag) {
            throw IllegalStateException("This key has already been destroyed.")
        }
        return keyMaterial.clone()
    }

    override fun destroy() {
        if (!isDestroyedFlag) {
            keyMaterial.fill(0)
            isDestroyedFlag = true
        }
    }

    override fun isDestroyed(): Boolean = isDestroyedFlag
}