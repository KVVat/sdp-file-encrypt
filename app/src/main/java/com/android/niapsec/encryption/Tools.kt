package com.android.niapsec.encryption

fun ByteArray.toHexDumpString(): String = buildString {
    for (rowAddr in this@toHexDumpString.indices step 16) {
        val rowEnd = minOf(rowAddr + 16, this@toHexDumpString.size)
        val rowBytes = this@toHexDumpString.sliceArray(rowAddr until rowEnd)

        // 1. アドレス (00000000)
        append("%08x  ".format(rowAddr))

        // 2. 16進数データ (48 65 6c...)
        val hexPart = rowBytes.joinToString(" ") { "%02x".format(it) }
        append(hexPart.padEnd(47)) // 16バイト分の幅を固定

        // 3. 可読文字 (Hello...)
        append("  |")
        rowBytes.forEach {
            val char = it.toInt().toChar()
            append(if (it in 32..126) char else '.')
        }
        append("|\n")
    }
}.trimEnd()