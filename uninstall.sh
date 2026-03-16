#!/bin/sh
adb shell dpm remove-active-admin com.android.niapsec/.demo.DeviceAdminReceiver
adb uninstall com.android.niapsec
