package com.android.niapsec.demo

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType

class MainActivity : ComponentActivity() {

    private val secureFileKeyUri = "android-keystore://secure_file_key"
    private val insecureFileKeyUri = "android-keystore://insecure_file_key"
    private val p521FileKeyUri = "android-keystore://p521_file_key"
    private val hybridFileKeyUri = "android-keystore://hybrid_file_key"
    private val securePrefsKeyUri = "android-keystore://secure_prefs_key"
    private lateinit var testRunner: EncryptionTestRunner

    private lateinit var devicePolicyManager: DevicePolicyManager
    private lateinit var compName: ComponentName

    private val secureManager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            secureFileKeyUri,
            providerType = KeyProviderType.SECURE,
            unlockedDeviceRequired = true
        )
    }

    private val p521Manager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            p521FileKeyUri,
            providerType = KeyProviderType.P521,
            unlockedDeviceRequired = true
        )
    }

    private val hybridManager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            hybridFileKeyUri,
            providerType = KeyProviderType.HYBRID,
            unlockedDeviceRequired = true
        )
    }

    private val insecureManager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            insecureFileKeyUri,
            providerType = KeyProviderType.INSECURE_SOFTWARE_ONLY
        )
    }

    private val requestAdminLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode != RESULT_OK) {
            Log.e("DeviceAdmin", "Failed to get device admin permission.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        testRunner = EncryptionTestRunner(this)
        devicePolicyManager = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        compName = ComponentName(this, DeviceAdminReceiver::class.java)
        setContent {
            TestButtons()
        }
    }

    @Composable
    private fun TestButtons() {
        Column(
            modifier = Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // File Encryption Tests
            Button(onClick = { runSecureFileTest() }) { Text("Test SECURE File") }
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { lockAndTest(KeyProviderType.SECURE) }) { Text("Lock & Test SECURE File") }

            // P521 File Encryption Tests
            Spacer(modifier = Modifier.height(32.dp))
            Button(onClick = { runP521FileTest() }) { Text("Test P521 File") }
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { lockAndTest(KeyProviderType.P521) }) { Text("Lock & Test P521 File") }

            // Hybrid File Encryption Tests
            Spacer(modifier = Modifier.height(32.dp))
            Button(onClick = { runHybridFileTest() }) { Text("Test HYBRID File") }
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { lockAndTest(KeyProviderType.HYBRID) }) { Text("Lock & Test HYBRID File") }

            // SharedPreferences Test
            Spacer(modifier = Modifier.height(32.dp))
            Button(onClick = { runEncryptedPrefsTest() }) { Text("Test EncryptedSharedPreferences") }
            
            // Cleanup
            Spacer(modifier = Modifier.height(32.dp))
            Button(onClick = { clearAll() }) { Text("Clear All Keys & Data") }
        }
    }

    private fun runSecureFileTest() {
        testRunner.runFullTest(secureManager, "SecureFileTest")
    }

    private fun runP521FileTest() {
        testRunner.runFullTest(p521Manager, "P521FileTest")
    }

    private fun runHybridFileTest() {
        testRunner.runFullTest(hybridManager, "HybridFileTest")
    }

    private fun runInsecureFileTest() {
        testRunner.runFullTest(insecureManager, "InsecureFileTest")
    }

    private fun runEncryptedPrefsTest() {
        val testTag = "EncryptedPrefsTest"
        val encryptedPrefs = EncryptedSharedPreferences(this, "my_secure_prefs", secureManager)
        val key = "my_secret_key"
        val originalValue = "This is a top secret message! ${System.currentTimeMillis()}"

        Log.d(testTag, "Saving value: $originalValue")
        encryptedPrefs.putString(key, originalValue)
        val retrievedValue = encryptedPrefs.getString(key, null)
        Log.d(testTag, "Retrieved value: $retrievedValue")

        if (originalValue == retrievedValue) {
            Log.d(testTag, "SUCCESS: Retrieved value matches original.")
        } else {
            Log.e(testTag, "FAILURE: Retrieved value does not match.")
        }
    }

    private fun lockAndTest(providerType: KeyProviderType) {
        if (!devicePolicyManager.isAdminActive(compName)) {
            requestDeviceAdmin()
            return
        }

        val manager = when (providerType) {
            KeyProviderType.SECURE -> secureManager
            KeyProviderType.P521 -> p521Manager
            KeyProviderType.HYBRID -> hybridManager
            else -> insecureManager
        }

        Log.d("LockAndTest", "Locking screen to test $providerType provider...")
        devicePolicyManager.lockNow()

        Handler(Looper.getMainLooper()).postDelayed({
            Log.d("LockAndTest", "Running $providerType test after delay...")
            val shouldFail = providerType == KeyProviderType.SECURE || providerType == KeyProviderType.P521 || providerType == KeyProviderType.HYBRID
            testRunner.runFullTest(manager, "${providerType}AfterLock", reverseDecryptionResult = shouldFail)
        }, 5000)
    }

    private fun requestDeviceAdmin() {
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, compName)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "This app needs permission to lock the screen for testing.")
        }
        requestAdminLauncher.launch(intent)
    }

    private fun clearAll() {
        // Destroy file-based keys
        secureManager.destroy()
        insecureManager.destroy()
        p521Manager.destroy()
        hybridManager.destroy()

        // Destroy and clear prefs-based keys and data
        val prefsManager = EncryptionManager(this, securePrefsKeyUri, KeyProviderType.SECURE)
        EncryptedSharedPreferences(this, "my_secure_prefs", prefsManager).clear()
        prefsManager.destroy()

        Log.d("ClearData", "All keys and data have been destroyed.")
    }
}
