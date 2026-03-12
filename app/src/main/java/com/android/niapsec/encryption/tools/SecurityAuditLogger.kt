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

    fun logKeyMaterial(tag: String, keyName: String, keyBytes: ByteArray?) {
        if (!isAuditLogEnabled || keyBytes == null) return

        Log.d(tag, "=== SECURITY AUDIT LOG: $keyName ===")
        Log.d(tag, "\n" + keyBytes.toHexDumpString())
    }
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