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
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.android.niapsec.demo.ui.theme.FileEncryptionLibTheme
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : ComponentActivity() {

    private val hybridFileKeyUri = "android-keystore://hybrid_file_key"
    private val rawFileKeyUri = "android-keystore://raw_file_key"
    private val rawHybridFileKeyUri = "android-keystore://raw_hybrid_file_key"
    private lateinit var testRunner: EncryptionTestRunner

    private lateinit var devicePolicyManager: DevicePolicyManager
    private lateinit var compName: ComponentName

    private val hybridManager: EncryptionManager by lazy {
        EncryptionManager(this, hybridFileKeyUri, providerType = KeyProviderType.HYBRID, unlockedDeviceRequired = true)
    }

    private val rawManager: EncryptionManager by lazy {
        EncryptionManager(this, rawFileKeyUri, providerType = KeyProviderType.RAW, unlockedDeviceRequired = true)
    }

    private val rawHybridManager: EncryptionManager by lazy {
        EncryptionManager(this, rawHybridFileKeyUri, providerType = KeyProviderType.RAW_HYBRID, unlockedDeviceRequired = true)
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
        val snackbarHostState = remember { SnackbarHostState() }
        val scope = rememberCoroutineScope()
        val showDeleteConfirmation = remember { mutableStateOf(false) }

        if (showDeleteConfirmation.value) {
            AlertDialog(
                onDismissRequest = { showDeleteConfirmation.value = false },
                title = { Text("Delete All Keys & Data?") },
                text = { Text("This will permanently destroy all cryptographic keys and encrypted files. This action cannot be undone.") },
                confirmButton = {
                    TextButton(
                        onClick = {
                            showDeleteConfirmation.value = false
                            clearAll()
                            scope.launch {
                                snackbarHostState.showSnackbar("All keys and data destroyed")
                            }
                        }
                    ) {
                        Text("Delete", color = MaterialTheme.colorScheme.error)
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showDeleteConfirmation.value = false }) {
                        Text("Cancel")
                    }
                }
            )
        }

        Scaffold(
            snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
            topBar = {
                TopAppBar(
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.VpnKey, contentDescription = "Encryption Key")
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("File Encryption Demo")
                        }
                    }
                )
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier.fillMaxSize().padding(innerPadding),
            ) {
                Column(
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    ProviderTestGroup(
                        title = "Tink HYBRID",
                        onTestClick = { runHybridFileTest() },
                        onLockAndTestClick = { lockAndTest(KeyProviderType.HYBRID) }
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    ProviderTestGroup(
                        title = "JCA RAW",
                        onTestClick = { runRawFileTest() },
                        onLockAndTestClick = { lockAndTest(KeyProviderType.RAW) }
                    )
                    Spacer(modifier = Modifier.height(16.dp))

                    ProviderTestGroup(
                        title = "JCA RAW HYBRID",
                        onTestClick = { runRawHybridFileTest() },
                        onLockAndTestClick = { lockAndTest(KeyProviderType.RAW_HYBRID) }
                    )

                    Spacer(modifier = Modifier.height(16.dp))
                    Button(onClick = { checkFileStatus() }) { Text("Check Status") }
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    Button(
                        onClick = { showDeleteConfirmation.value = true },
                        colors = androidx.compose.material3.ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.error
                        )
                    ) { 
                        Text("Clear All Keys & Data") 
                    }
                }
                Divider(modifier = Modifier.fillMaxWidth())
                LazyColumn(modifier = Modifier.weight(1f)) {
                    items(testResults.value) { result ->
                        TestResultRow(result) {
                            result.file?.let { file ->
                                scope.launch {
                                    try {
                                        val header = readHeader(file)
                                        val manager = when (header) {
                                            "ERAW" -> rawManager
                                            "EHBT" -> hybridManager
                                            "EHBR" -> rawHybridManager
                                            else -> rawHybridManager // Default fallback
                                        }
                                        val plaintext = manager.decryptFromFile(file).use { it.reader().readText() }
                                        snackbarHostState.showSnackbar("Decrypted: $plaintext")
                                    } catch (e: Exception) {
                                        snackbarHostState.showSnackbar("Decryption failed: ${e.message}")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun readHeader(file: File): String {
        return try {
            val input = file.inputStream()
            val headerBytes = ByteArray(4)
            val read = input.read(headerBytes)
            input.close()
            if (read == 4) String(headerBytes) else ""
        } catch (e: Exception) { "" }
    }

    private fun checkFileStatus() {
        val results = mutableListOf<TestResult>()
        val files = filesDir.listFiles()?.filter { it.name.endsWith(".enc") } ?: emptyList()

        if (files.isEmpty()) {
            results.add(TestResult("File Status", true, "No .enc files found"))
        } else {
            files.forEach { file ->
                try {
                    val header = readHeader(file)
                    val status = when (header) {
                        "EHBT" -> "Tink Hybrid (EHBT)"
                        "ERAW" -> "JCA Raw (ERAW)"
                        "EHBR" -> {
                            val input = file.inputStream()
                            input.skip(4) // Skip EHBR
                            val magic = input.read()
                            input.close()
                            when (magic) {
                                0x01 -> "JCA RawHybrid (Asymmetric 0x01)"
                                0x02 -> "JCA RawHybrid (Symmetric 0x02)"
                                else -> "JCA RawHybrid (EHBR, Unknown Magic)"
                            }
                        }
                        else -> "Unknown Header: $header"
                    }
                    results.add(TestResult(file.name, true, status, file))
                } catch (e: Exception) {
                    results.add(TestResult(file.name, false, "Error reading file", file))
                }
            }
        }
        testResults.value = results
    }

    @Composable
    private fun TestResultRow(result: TestResult, onClick: () -> Unit) {
        val isFileStatus = result.file != null
        Row(
            modifier = Modifier
                .padding(8.dp)
                .fillMaxWidth()
                .clickable(enabled = isFileStatus) { onClick() },
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = if (result.passed) Icons.Default.CheckCircle else Icons.Default.Warning,
                contentDescription = if (result.passed) "Passed" else "Failed",
                tint = if (result.passed) Color.Green else Color.Red
            )
            Spacer(modifier = Modifier.width(8.dp))
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
                if (isFileStatus) {
                    Text(
                        text = "Tap to decrypt ${result.file?.name}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
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
        testResults.value = testRunner.runFullTest(hybridManager, "TinkHybridFileTest")
    }

    private fun runRawFileTest() {
        testResults.value = testRunner.runFullTest(rawManager, "JcaRawFileTest")
    }

    private fun runRawHybridFileTest() {
        testResults.value = testRunner.runFullTest(rawHybridManager, "JcaRawHybridFileTest")
    }

    private fun lockAndTest(providerType: KeyProviderType) {
        if (!devicePolicyManager.isAdminActive(compName)) {
            requestDeviceAdmin()
            return
        }

        val manager = when (providerType) {
            KeyProviderType.HYBRID -> hybridManager
            KeyProviderType.RAW -> rawManager
            KeyProviderType.RAW_HYBRID -> rawHybridManager
            else -> throw IllegalArgumentException("Unsupported provider type: $providerType")
        }

        val keyguardManager = getSystemService(KEYGUARD_SERVICE) as android.app.KeyguardManager
        Log.d("LockAndTest", "Locking screen to test $providerType provider...")
        devicePolicyManager.lockNow()

        // [Phase 1.2] Poll for device locked state every 200ms to proceed as fast as possible
        val handler = Handler(Looper.getMainLooper())
        val startTime = System.currentTimeMillis()
        val timeoutMs = 5000L // Safety timeout

        val checkStateRunnable = object : Runnable {
            override fun run() {
                val isLocked = keyguardManager.isDeviceLocked
                val elapsed = System.currentTimeMillis() - startTime
                
                if (isLocked) {
                    Log.d("LockAndTest", "Device is LOCKED after ${elapsed}ms. Proceeding with test.")
                    val shouldFail = true
                    testResults.value = testRunner.runFullTest(manager, "${providerType}AfterLock", reverseDecryptionResult = shouldFail)
                } else if (elapsed < timeoutMs) {
                    // Not locked yet, poll again
                    handler.postDelayed(this, 200)
                } else {
                    Log.e("LockAndTest", "Timeout waiting for device to lock. Proceeding anyway.")
                    val shouldFail = true
                    testResults.value = testRunner.runFullTest(manager, "${providerType}AfterLock", reverseDecryptionResult = shouldFail)
                }
            }
        }
        handler.postDelayed(checkStateRunnable, 200)
    }

    private fun requestDeviceAdmin() {
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, compName)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, "This app needs permission to lock the screen for testing.")
        }
        requestAdminLauncher.launch(intent)
    }

    private fun clearAll() {
        hybridManager.destroy()
        rawManager.destroy()
        rawHybridManager.destroy()
        testResults.value = emptyList()
        Log.d("ClearData", "All keys and data have been destroyed.")
    }
}
