package com.android.niapsec.demo

import android.app.admin.DevicePolicyManager
import android.app.admin.DeviceAdminReceiver
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.Toast

class DeviceAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Toast.makeText(context, "Device admin enabled", Toast.LENGTH_SHORT).show()
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Toast.makeText(context, "Device admin disabled", Toast.LENGTH_SHORT).show()
    }
}

class RemoveAdminReceiver : BroadcastReceiver() {
    companion object {
        const val ACTION_REMOVE_ADMIN = "com.android.niapsec.demo.ACTION_REMOVE_ADMIN"
    }

    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != ACTION_REMOVE_ADMIN) return
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val component = ComponentName(context, DeviceAdminReceiver::class.java)
        if (dpm.isAdminActive(component)) {
            dpm.removeActiveAdmin(component)
            Log.d("RemoveAdmin", "Device admin removed")
        }
    }
}