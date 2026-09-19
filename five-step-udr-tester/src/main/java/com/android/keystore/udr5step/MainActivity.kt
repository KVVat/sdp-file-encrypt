/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Standalone One-Button RawKeyProvider Lock & Test Verifier (b/499946994)
 *
 * Pressing the single button locks the device via DevicePolicyManager.lockNow(),
 * waits for KeyguardManager.isDeviceLocked == true, and executes EncryptionManager
 * with KeyProviderType.RAW (RawKeyProvider, unlockedDeviceRequired = true):
 *   1. While LOCKED:
 *      - Encrypts test file via RawKeyProvider (generates AES-256 key in software, encrypts file,
 *        and imports key into AndroidKeyStore with setUnlockedDeviceRequired(true)).
 *      - Attempts decryption while LOCKED (verifies it fails as expected).
 *   2. Upon UNLOCK (Intent.ACTION_USER_PRESENT):
 *      - Automatically decrypts the file while unlocked using the imported AndroidKeyStore key.
 */
package com.android.keystore.udr5step

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType
import java.io.File
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

class MainActivity : ComponentActivity() {

    companion object {
        const val TAG = "RawKeyProviderTester"
        private const val RAW_KEY_URI = "android-keystore://raw_file_key"
        private const val TEST_FILE_NAME = "RawKeyProvider-Locked-test_file.enc"
        private const val ORIGINAL_TEXT = "This is a secret message encrypted by RawKeyProvider while locked."

        @Volatile
        var lastGeneratedKeyHex: String = ""
    }

    private lateinit var devicePolicyManager: DevicePolicyManager
    private lateinit var compName: ComponentName
    private var _rawManager: EncryptionManager? = null
    private val rawManager: EncryptionManager
        get() {
            if (_rawManager == null) {
                _rawManager = EncryptionManager(
                    context = this,
                    masterKeyUri = RAW_KEY_URI,
                    providerType = KeyProviderType.RAW,
                    unlockedDeviceRequired = true
                )
            }
            return _rawManager!!
        }

    private var outputTextState by mutableStateOf(
        "Tap the button below to lock the device and run RawKeyProvider (UDR=true) Lock & Test."
    )

    private val requestAdminLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK || devicePolicyManager.isAdminActive(compName)) {
            lockAndRunRawKeyProviderTest()
        } else {
            appendLog("[ERROR] Device Admin permission was not granted. Cannot auto-lock screen.")
        }
    }

    private val unlockReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == Intent.ACTION_USER_PRESENT) {
                Log.i(TAG, "Device unlocked (ACTION_USER_PRESENT). Running unlocked decryption verification...")
                verifyDecryptionAfterUnlock()
            }
        }
    }

    /**
     * Installs a transparent JCA KeyGenerator observer on "AndroidOpenSSL" so we can log the exact
     * 32-byte AES key generated inside RawKeyProvider.generateEphemeralSoftwareKey() without
     * modifying RawKeyProvider itself.
     */
    private fun installKeyObserverOnAndroidOpenSSL() {
        val openSslProvider = Security.getProvider("AndroidOpenSSL") ?: return
        val originalService = openSslProvider.getService("KeyGenerator", "AES") ?: return
        if (openSslProvider.getProperty("RawKeyObserverInstalled") == "true") return

        openSslProvider.put("RawKeyObserverInstalled", "true")
        val putServiceMethod = Provider::class.java.getDeclaredMethod("putService", Provider.Service::class.java)
        putServiceMethod.isAccessible = true
        putServiceMethod.invoke(
            openSslProvider,
            object : Provider.Service(
                openSslProvider,
                "KeyGenerator",
                "AES",
                ObservingAesKeyGeneratorSpi::class.java.name,
                emptyList(),
                emptyMap()
            ) {
                override fun newInstance(constructorParameter: Any?): Any {
                    val ctor = Class.forName(originalService.className).getDeclaredConstructor()
                    ctor.isAccessible = true
                    val delegateSpi = ctor.newInstance() as KeyGeneratorSpi
                    return ObservingAesKeyGeneratorSpi(delegateSpi)
                }
            }
        )
    }

    class ObservingAesKeyGeneratorSpi(private val delegate: KeyGeneratorSpi) : KeyGeneratorSpi() {
        override fun engineInit(random: SecureRandom?) {
            val m = KeyGeneratorSpi::class.java.getDeclaredMethod("engineInit", SecureRandom::class.java)
            m.isAccessible = true
            m.invoke(delegate, random)
        }

        override fun engineInit(params: java.security.spec.AlgorithmParameterSpec?, random: SecureRandom?) {
            val m = KeyGeneratorSpi::class.java.getDeclaredMethod(
                "engineInit",
                java.security.spec.AlgorithmParameterSpec::class.java,
                SecureRandom::class.java
            )
            m.isAccessible = true
            m.invoke(delegate, params, random)
        }

        override fun engineInit(keysize: Int, random: SecureRandom?) {
            val m = KeyGeneratorSpi::class.java.getDeclaredMethod(
                "engineInit",
                Int::class.javaPrimitiveType,
                SecureRandom::class.java
            )
            m.isAccessible = true
            m.invoke(delegate, keysize, random)
        }

        override fun engineGenerateKey(): SecretKey {
            val m = KeyGeneratorSpi::class.java.getDeclaredMethod("engineGenerateKey")
            m.isAccessible = true
            val secretKey = m.invoke(delegate) as SecretKey
            // Read the internal byte[] field directly via reflection (without calling .encoded)
            // so this observer creates ZERO extra byte[] clones on the heap!
            try {
                var clazz: Class<*>? = secretKey.javaClass
                while (clazz != null) {
                    for (field in clazz.declaredFields) {
                        if (field.type == ByteArray::class.java) {
                            field.isAccessible = true
                            val internalBytes = field.get(secretKey) as? ByteArray
                            if (internalBytes != null) {
                                lastGeneratedKeyHex = internalBytes.joinToString("") { "%02x".format(it) }
                            }
                        }
                    }
                    clazz = clazz.superclass
                }
            } catch (_: Exception) {
            }
            return secretKey
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        installKeyObserverOnAndroidOpenSSL()
        devicePolicyManager = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        compName = ComponentName(this, DeviceAdminReceiver::class.java)
        registerReceiver(unlockReceiver, IntentFilter(Intent.ACTION_USER_PRESENT))

        val autoRun = intent?.getBooleanExtra("auto_run", false) ?: false
        if (autoRun) {
            Handler(Looper.getMainLooper()).post {
                lockAndRunRawKeyProviderTest()
            }
        }

        setContent {
            MaterialTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    OneButtonRawKeyScreen(
                        modifier = Modifier.padding(innerPadding),
                        outputText = outputTextState,
                        onLockAndTestClick = { lockAndRunRawKeyProviderTest() }
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        unregisterReceiver(unlockReceiver)
    }

    private fun appendLog(line: String) {
        outputTextState = if (outputTextState.isEmpty()) line else "$outputTextState\n$line"
        Log.i(TAG, line)
    }

    private fun lockAndRunRawKeyProviderTest() {
        if (!devicePolicyManager.isAdminActive(compName)) {
            val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, compName)
                putExtra(
                    DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Required to lock the screen for RawKeyProvider (UDR) Lock & Test."
                )
            }
            requestAdminLauncher.launch(intent)
            return
        }

        outputTextState = "==================================================\n" +
            "RawKeyProvider (UDR=true) Lock & Test\n" +
            "==================================================\n" +
            "[1] Calling DevicePolicyManager.lockNow()..."
        Log.i(TAG, "Locking screen via DevicePolicyManager.lockNow()...")
        devicePolicyManager.lockNow()

        val keyguardManager = getSystemService(KEYGUARD_SERVICE) as KeyguardManager
        val handler = Handler(Looper.getMainLooper())
        val startTime = System.currentTimeMillis()
        val timeoutMs = 5000L

        val checkStateRunnable = object : Runnable {
            override fun run() {
                val isLocked = keyguardManager.isDeviceLocked
                val elapsed = System.currentTimeMillis() - startTime
                if (isLocked || elapsed >= timeoutMs) {
                    appendLog("[2] Device is LOCKED (isDeviceLocked=$isLocked, elapsed=${elapsed}ms).")
                    executeLockedRawKeyProviderPhase()
                } else {
                    handler.postDelayed(this, 200)
                }
            }
        }
        handler.postDelayed(checkStateRunnable, 200)
    }

    private fun executeLockedRawKeyProviderPhase() {
        val file = File(filesDir, TEST_FILE_NAME)
        if (file.exists()) file.delete()

        // Phase A: Encrypt while LOCKED using EncryptionManager(KeyProviderType.RAW, unlockedDeviceRequired=true)
        try {
            rawManager.encryptToFile(file).use { it.write(ORIGINAL_TEXT.toByteArray(Charsets.UTF_8)) }
            val keyHex = lastGeneratedKeyHex
            File(filesDir, "target_5step_key.txt").writeText("TARGET_RAW_KEY_HEX=$keyHex\n")

            appendLog("[3] LOCKED Encryption (RawKeyProvider): SUCCESS")
            appendLog("    TARGET_RAW_KEY_HEX=$keyHex")
        } catch (e: Exception) {
            appendLog("[3] LOCKED Encryption FAILED: ${e.javaClass.simpleName}: ${e.message}")
            return
        }

        // Phase B: Attempt Decryption while LOCKED (Expected to FAIL because unlockedDeviceRequired=true)
        try {
            val text = rawManager.decryptFromFile(file).use { it.reader().readText() }
            appendLog("[4] LOCKED Decryption: UNEXPECTED SUCCESS ($text)")
        } catch (e: Exception) {
            appendLog("[4] LOCKED Decryption: REJECTED AS EXPECTED (${e.javaClass.simpleName})")
        }

        appendLog("--------------------------------------------------")
        appendLog("[Ready for Memory Dump / Unlock device to verify Step 5 Decryption]")
    }

    private fun verifyDecryptionAfterUnlock() {
        val file = File(filesDir, TEST_FILE_NAME)
        if (!file.exists()) return
        try {
            val decryptedText = rawManager.decryptFromFile(file).use { it.reader().readText() }
            val matches = (decryptedText == ORIGINAL_TEXT)
            appendLog("[5] UNLOCKED Decryption (ACTION_USER_PRESENT): ${if (matches) "SUCCESS (Content matches)" else "MISMATCH"}")
            appendLog("    Decrypted: \"$decryptedText\"")
        } catch (e: Exception) {
            appendLog("[5] UNLOCKED Decryption FAILED: ${e.javaClass.simpleName}: ${e.message}")
        }
    }
}

@Composable
fun OneButtonRawKeyScreen(
    modifier: Modifier = Modifier,
    outputText: String,
    onLockAndTestClick: () -> Unit
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(
            text = "RawKeyProvider Lock & Test",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )
        Text(
            text = "One-Button Lock & Test using EncryptionManager (KeyProviderType.RAW, unlockedDeviceRequired = true).\n" +
                "Pressing the button locks the device, encrypts a file while locked, verifies decryption fails while locked, and decrypts upon unlock.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Button(
            onClick = onLockAndTestClick,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFB71C1C))
        ) {
            Text(
                text = "LOCK & TEST (RAWKEYPROVIDER)",
                fontWeight = FontWeight.Bold,
                fontSize = 14.sp
            )
        }

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            shape = RoundedCornerShape(8.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF121212))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = outputText,
                    color = Color(0xFF69F0AE),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                )
            }
        }
    }
}
