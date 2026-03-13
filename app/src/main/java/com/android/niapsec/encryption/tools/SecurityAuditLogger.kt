package com.android.niapsec.encryption.tools

import android.util.Log


/**
 * [Security Component: Audit Logger]
 * NIAP/MDFPPラボ評価時の鍵確証エビデンスを取得するためのモジュール。
 * 本番リリース時は [isAuditLogEnabled] を必ず false に設定すること。
 */
object SecurityAuditLogger {
    // 監査用トグルスイッチ
    var isAuditLogEnabled = true

    private const val TAG = "AUDIT_LOGGER KMD"

    fun logMaterial(tag: String = TAG, name: String, bytes: ByteArray?) {
        if (!isAuditLogEnabled || bytes == null) return
        Log.d(tag,  bytes.toHexDumpString())
    }

    fun logKeyMaterial(name: String, bytes: ByteArray?) {
        return logKeyMaterial(tag = TAG, name = name, bytes = bytes);
    }
    fun logKeyMaterial(tag: String= TAG, name: String, bytes: ByteArray?) {
        if (!isAuditLogEnabled || bytes== null) return

        Log.d(tag, "=== SECURITY AUDIT KEY MATERIAL: $name ===")
        Log.d(tag,  bytes.toHexString())
    }
}

fun ByteArray.toHexString(): String {
    return joinToString("") { "%02x".format(it) }
}
fun ByteArray.toHexDumpString(): String = buildString {
    for (rowAddr in this@toHexDumpString.indices step 16) {
        val rowEnd = minOf(rowAddr + 16, this@toHexDumpString.size)
        val rowBytes = this@toHexDumpString.sliceArray(rowAddr until rowEnd)

        append("%08x  ".format(rowAddr))

        val hexPart = rowBytes.joinToString(" ") { "%02x".format(it) }
        append(hexPart.padEnd(47)) // 16バイト分の幅を固定

        append("  |")
        rowBytes.forEach {
            val char = it.toInt().toChar()
            append(if (it in 32..126) char else '.')
        }
        append("|\n")
    }
}.trimEnd()