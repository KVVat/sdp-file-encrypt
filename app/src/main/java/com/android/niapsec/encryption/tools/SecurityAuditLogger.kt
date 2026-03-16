package com.android.niapsec.encryption.tools

import android.util.Log


/**
 * [Security Component: Audit Logger]
 *
 * [isAuditLogEnabled] should be false when the app is released.
 */
object SecurityAuditLogger {
    // toggle switch for audit
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
        if (!isAuditLogEnabled || bytes== null) {
            Log.d("${name} KMD",  "returns null (error or hardware backend)")
            return
        }
        Log.d("${name} KMD",  bytes.toHexString())
        bytes.fill(0)
    }

    fun logLine(msg: String) {
        logLine(tag = TAG, msg = msg)
    }
    fun logLine(tag:String,msg: String) {
        Log.d(tag,msg)
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