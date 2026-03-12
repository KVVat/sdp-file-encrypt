package com.android.niapsec.encryption.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class DeviceUnlockReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_USER_UNLOCKED) {
            Log.d("DeviceUnlockReceiver", "User unlocked device. Starting key re-wrap sweep...")

            // TODO: バックグラウンドスレッド（CoroutinesやWorkManager）で
            // EncryptionManager の sweepAndRewrapPendingFiles() を呼び出す

            /* 例:
            CoroutineScope(Dispatchers.IO).launch {
                encryptionManager.sweepAndRewrapPendingFiles()
            }
            */
        }
    }
}