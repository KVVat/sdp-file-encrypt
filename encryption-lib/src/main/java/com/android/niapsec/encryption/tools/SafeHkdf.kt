package com.android.niapsec.encryption.tools
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.math.ceil

object SafeHkdf {
    private const val SHA256_BLOCK_SIZE = 64
    private const val SHA256_HASH_SIZE = 32

    /**
     * JNIのMacを使わず、MessageDigestのみでHMAC-SHA256を計算する
     */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        val paddedKey = ByteArray(SHA256_BLOCK_SIZE)

        // HMACの仕様に基づく鍵のパディング
        if (key.size > SHA256_BLOCK_SIZE) {
            val hashedKey = md.digest(key)
            System.arraycopy(hashedKey, 0, paddedKey, 0, hashedKey.size)
            hashedKey.fill(0) // 中間バッファを即座にクリア
        } else {
            System.arraycopy(key, 0, paddedKey, 0, key.size)
        }

        val oPad = ByteArray(SHA256_BLOCK_SIZE)
        val iPad = ByteArray(SHA256_BLOCK_SIZE)

        for (i in 0 until SHA256_BLOCK_SIZE) {
            oPad[i] = (paddedKey[i].toInt() xor 0x5c).toByte()
            iPad[i] = (paddedKey[i].toInt() xor 0x36).toByte()
        }

        // Inner hash: H(iPad || data)
        md.reset()
        md.update(iPad)
        md.update(data)
        val innerHash = md.digest()

        // Outer hash: H(oPad || innerHash)
        md.reset()
        md.update(oPad)
        md.update(innerHash)
        val mac = md.digest()

        // 【最重要】使用後のバッファを確実にゼロクリア
        paddedKey.fill(0)
        oPad.fill(0)
        iPad.fill(0)
        innerHash.fill(0)

        return mac
    }

    /**
     * Tinkの Hkdf.computeHkdf と完全に互換性のある関数
     */
    fun computeHkdf(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(SHA256_HASH_SIZE) else salt

        // 1. HKDF-Extract
        val prk = hmacSha256(actualSalt, ikm)

        // 2. HKDF-Expand
        val result = ByteArrayOutputStream()
        var t = ByteArray(0)
        val iterations = ceil(length.toDouble() / SHA256_HASH_SIZE).toInt()

        require(iterations <= 255) { "Requested length is too large" }

        for (i in 1..iterations) {
            val input = ByteArray(t.size + info.size + 1)
            System.arraycopy(t, 0, input, 0, t.size)
            System.arraycopy(info, 0, input, t.size, info.size)
            input[input.size - 1] = i.toByte()

            if (t.isNotEmpty()) t.fill(0) // 前回のTをクリア

            t = hmacSha256(prk, input)
            result.write(t)

            input.fill(0) // ループ内の一時バッファをクリア
        }

        val finalResult = result.toByteArray().copyOf(length)

        // 【最重要】PRK と 最後の T をゼロクリア
        prk.fill(0)
        t.fill(0)

        // メモ: 呼び出し元(RawHybridKeyProvider)の finally ブロックで
        // 実際の ikm (sharedSecret) はクリアされる想定です。

        return finalResult
    }
}