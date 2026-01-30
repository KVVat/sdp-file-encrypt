/*
* Copyright (C) 2026 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
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
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.android.niapsec.demo.ui.theme.FileEncryptionLibTheme
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType

class MainActivity : ComponentActivity() {

    private val hybridFileKeyUri = "android-keystore://hybrid_file_key"
    private val rawFileKeyUri = "android-keystore://raw_file_key"
    private lateinit var testRunner: EncryptionTestRunner

    private lateinit var devicePolicyManager: DevicePolicyManager
    private lateinit var compName: ComponentName

    private val hybridManager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            hybridFileKeyUri,
            providerType = KeyProviderType.HYBRID,
            unlockedDeviceRequired = true
        )
    }

    private val rawManager: EncryptionManager by lazy {
        EncryptionManager(
            this,
            rawFileKeyUri,
            providerType = KeyProviderType.RAW,
            unlockedDeviceRequired = true
        )
    }

    private val testResults = mutableStateOf<List<TestResult>>(emptyList())

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
            FileEncryptionLibTheme {
                TestScreen()
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun TestScreen() {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.VpnKey, contentDescription = "Encryption Key")
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("File Encryption Demo")
                        }
                    }
                )
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding),
            ) {
                Column(
                    modifier = Modifier.weight(1f).fillMaxWidth(),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    ProviderTestGroup(
                        title = "HYBRID (P-521 KEK + AES-256 DEK)",
                        onTestClick = { runHybridFileTest() },
                        onLockAndTestClick = { lockAndTest(KeyProviderType.HYBRID) }
                    )
                    Spacer(modifier = Modifier.height(24.dp))

                    ProviderTestGroup(
                        title = "RAW (JCA with AES-GCM)",
                        onTestClick = { runRawFileTest() },
                        onLockAndTestClick = { lockAndTest(KeyProviderType.RAW) }
                    )

                    // Cleanup
                    Spacer(modifier = Modifier.height(32.dp))
                    Button(onClick = { clearAll() }) { Text("Clear All Keys & Data") }
                }
                Divider(modifier = Modifier.fillMaxWidth())
                TestResultsList(modifier = Modifier.weight(1f))
            }
        }
    }

    @Composable
    private fun TestResultsList(modifier: Modifier = Modifier) {
        LazyColumn(modifier = modifier) {
            items(testResults.value) { result ->
                Row(
                    modifier = Modifier.padding(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (result.passed) Icons.Default.CheckCircle else Icons.Default.Warning,
                        contentDescription = if (result.passed) "Passed" else "Failed",
                        tint = if (result.passed) Color.Green else Color.Red
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Column {
                        Text(
                            text = result.testName,
                            style = MaterialTheme.typography.bodyLarge,
                            color = if (result.passed) Color.Unspecified else Color.Red
                        )
                        Text(
                            text = result.message,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (result.passed) Color.Unspecified else Color.Red
                        )
                    }
                }
            }
        }
    }

    @Composable
    private fun ProviderTestGroup(title: String, onTestClick: () -> Unit, onLockAndTestClick: () -> Unit) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(text = title, style = MaterialTheme.typography.titleLarge)
            Spacer(modifier = Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                Button(onClick = onTestClick) { Text("Test File") }
                Button(onClick = onLockAndTestClick) { Text("Lock & Test") }
            }
        }
    }

    private fun runHybridFileTest() {
        testResults.value = testRunner.runFullTest(hybridManager, "HybridFileTest")
    }

    private fun runRawFileTest() {
        testResults.value = testRunner.runFullTest(rawManager, "RawFileTest")
    }

    private fun lockAndTest(providerType: KeyProviderType) {
        if (!devicePolicyManager.isAdminActive(compName)) {
            requestDeviceAdmin()
            return
        }

        val manager = when (providerType) {
            KeyProviderType.HYBRID -> hybridManager
            KeyProviderType.RAW -> rawManager
            else -> throw IllegalArgumentException("Unsupported provider type: $providerType")
        }

        Log.d("LockAndTest", "Locking screen to test $providerType provider...")
        devicePolicyManager.lockNow()

        Handler(Looper.getMainLooper()).postDelayed({
            Log.d("LockAndTest", "Running $providerType test after delay...")
            val shouldFail = true // All secure providers should fail when locked
            testResults.value = testRunner.runFullTest(manager, "${providerType}AfterLock", reverseDecryptionResult = shouldFail)
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
        hybridManager.destroy()
        rawManager.destroy()
        testResults.value = emptyList()

        Log.d("ClearData", "All keys and data have been destroyed.")
    }
}
