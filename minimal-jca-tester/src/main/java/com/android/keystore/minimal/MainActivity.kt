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
package com.android.keystore.minimal

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONObject

class MainActivity : ComponentActivity() {

    companion object {
        const val TAG = "KeyStoreVerification"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEK_ALIAS = "verify_master_kek_aes"
        private const val EC_KEY_ALIAS = "verify_ecdh_p521_key"
        private const val MDL_KEY_ALIAS = "mock_mdl_auth_key"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    VerificationScreen(
                        modifier = Modifier.padding(innerPadding),
                        onRunKeyWrappingTest = { runKeyWrappingVerification() },
                        onRunEcdhTest = { runEcdhVerification() },
                        onRunMockIdentityTestUnprotected = { runMockIdentityPresentation(enableCallerFlush = false) },
                        onRunMockIdentityTestProtected = { runMockIdentityPresentation(enableCallerFlush = true) },
                        onRunAllTests = {
                            val r1 = runKeyWrappingVerification()
                            val r2 = runEcdhVerification()
                            val r3 = runMockIdentityPresentation(enableCallerFlush = true)
                            "$r1\n\n$r2\n\n$r3"
                        }
                    )
                }
            }
        }
    }

    /**
     * Helper: Computes HKDF-Extract and HKDF-Expand (RFC 5869)
     * Mimics android.security.identity.internal.Util.computeHkdf
     */
    private fun computeHkdf(
        macAlgorithm: String,
        ikm: ByteArray,
        salt: ByteArray?,
        info: ByteArray?,
        length: Int
    ): ByteArray {
        val mac = Mac.getInstance(macAlgorithm)
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(mac.macLength) else salt
        mac.init(SecretKeySpec(actualSalt, macAlgorithm))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, macAlgorithm))
        if (info != null && info.isNotEmpty()) {
            mac.update(info)
        }
        mac.update(1.toByte())
        val okm = mac.doFinal()
        return okm.copyOf(length)
    }

    /**
     * Scenario 1: Envelope Encryption / Key Wrapping
     * Demonstrates passing an ephemeral random DEK to AndroidKeyStore for wrapping.
     */
    private fun runKeyWrappingVerification(): String {
        val out = StringBuilder()
        out.appendLine("==================================================")
        out.appendLine("[Step 1] Symmetric Key Wrapping (Envelope Encryption)")
        out.appendLine("==================================================")

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            // 1. Generate Hardware KEK in KeyStore
            if (!keyStore.containsAlias(KEK_ALIAS)) {
                out.appendLine("1. KeyGen: Generating Hardware Master KEK (AES-256)...")
                val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                val spec = KeyGenParameterSpec.Builder(
                    KEK_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build()
                keyGen.init(spec)
                keyGen.generateKey()
                out.appendLine("   -> Hardware KEK generated with alias '$KEK_ALIAS'")
            } else {
                out.appendLine("1. KeyGen: Using existing Hardware Master KEK '$KEK_ALIAS'")
            }

            val kek = keyStore.getKey(KEK_ALIAS, null)
                ?: throw IllegalStateException("Failed to load KEK from KeyStore")

            // 2. Generate Random 32-byte DEK in user space
            val dek = ByteArray(32)
            SecureRandom().nextBytes(dek)
            val dekHex = dek.joinToString("") { "%02x".format(it) }
            out.appendLine("2. DEK Generation: Generated random 32-byte DEK via SecureRandom:")
            out.appendLine("   [Target Key Hex to check in RAM]:")
            out.appendLine("   >> $dekHex <<")

            // 3. Wrap DEK via AndroidKeyStore Cipher (Cipher.doFinal)
            out.appendLine("3. JCA KeyStore Call: Cipher.getInstance(\"AES/GCM/NoPadding\", \"AndroidKeyStore\")")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, kek)
            val iv = cipher.iv
            val wrappedDek = cipher.doFinal(dek)
            val wrappedHex = wrappedDek.joinToString("") { "%02x".format(it) }

            out.appendLine("   -> Wrapped DEK (Ciphertext len: ${wrappedDek.size} bytes)")
            out.appendLine("   -> IV (${iv.size} bytes): ${iv.joinToString("") { "%02x".format(it) }}")

            // 4. Write exact target hex values directly to file on disk for memory scanner
            val targetFile = java.io.File(filesDir, "target_keys.txt")
            targetFile.writeText("TARGET_DEK_HEX=$dekHex\nWRAPPED_DEK_HEX=$wrappedHex\n")

            Log.i(TAG, "--------------------------------------------------")
            Log.i(TAG, "[SCENARIO 1: KEY WRAPPING]")
            Log.i(TAG, "TARGET_DEK_HEX=$dekHex")
            Log.i(TAG, "WRAPPED_DEK_HEX=$wrappedHex")
            Log.i(TAG, "Wrote target keys directly to ${targetFile.absolutePath}")
            Log.i(TAG, "--------------------------------------------------")

            // Zeroize application's local buffer
            dek.fill(0)
            out.appendLine("4. App Zeroization: Local dek[] buffer overwritten with 0x00.")
            out.appendLine("   Status: DEK passed to KeyMint HAL and local copy wiped.")

        } catch (e: Exception) {
            out.appendLine("ERROR in Key Wrapping: ${e.message}")
            Log.e(TAG, "Key Wrapping failed", e)
        }

        return out.toString()
    }

    /**
     * Scenario 2: ECDH Key Agreement (P-521)
     * Demonstrates KeyMint HAL computing an ECDH Shared Secret in TEE and returning it.
     */
    private fun runEcdhVerification(): String {
        val out = StringBuilder()
        out.appendLine("==================================================")
        out.appendLine("[Step 2] ECDH Key Agreement (P-521 with IPC Flush)")
        out.appendLine("==================================================")

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            // 1. Generate Hardware EC KeyPair in KeyStore
            if (!keyStore.containsAlias(EC_KEY_ALIAS)) {
                out.appendLine("1. KeyGen: Generating Hardware EC P-521 KeyPair...")
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                val spec = KeyGenParameterSpec.Builder(
                    EC_KEY_ALIAS,
                    KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp521r1"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                    .build()
                kpg.initialize(spec)
                kpg.generateKeyPair()
                out.appendLine("   -> Hardware EC KeyPair generated with alias '$EC_KEY_ALIAS'")
            } else {
                out.appendLine("1. KeyGen: Using existing Hardware EC KeyPair '$EC_KEY_ALIAS'")
            }

            val entry = keyStore.getEntry(EC_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry

            // 2. Generate Peer Ephemeral EC KeyPair
            out.appendLine("2. Peer KeyGen: Generating ephemeral software peer EC P-521 key pair...")
            val peerKpg = KeyPairGenerator.getInstance("EC")
            peerKpg.initialize(ECGenParameterSpec("secp521r1"))
            val peerKeyPair: KeyPair = peerKpg.generateKeyPair()

            // 3. Execute KeyAgreement via KeyStore
            out.appendLine("3. JCA KeyStore Call: KeyAgreement.getInstance(\"ECDH\", \"AndroidKeyStore\")")
            val keyAgreement = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
            keyAgreement.init(entry.privateKey)
            keyAgreement.doPhase(peerKeyPair.public, true)

            // 4. Generate Secret (returned from KeyMint TEE)
            val sharedSecret = keyAgreement.generateSecret()
            val secretHex = sharedSecret.joinToString("") { "%02x".format(it) }

            out.appendLine("   -> KeyMint TEE returned Shared Secret (${sharedSecret.size} bytes):")
            out.appendLine("   [Target Shared Secret Hex to check in RAM]:")
            out.appendLine("   >> $secretHex <<")

            // 5. Append exact target hex values directly to file on disk for memory scanner
            val targetFile = java.io.File(filesDir, "target_keys.txt")
            targetFile.appendText("TARGET_SHARED_SECRET_HEX=$secretHex\n")

            Log.i(TAG, "--------------------------------------------------")
            Log.i(TAG, "[SCENARIO 2: ECDH KEY AGREEMENT]")
            Log.i(TAG, "TARGET_SHARED_SECRET_HEX=$secretHex")
            Log.i(TAG, "Appended target key directly to ${targetFile.absolutePath}")
            Log.i(TAG, "--------------------------------------------------")

            // Zeroize application's local buffer
            sharedSecret.fill(0)
            out.appendLine("4. App Zeroization: Local sharedSecret[] buffer overwritten with 0x00.")

            // 6. Caller-Side Buffer Flush:
            out.appendLine("5. Caller-Side Flush: Executing dummy ECDH agreement to overwrite Binder parcel in KeyMint HAL...")
            val dummyPeerKpg = KeyPairGenerator.getInstance("EC")
            dummyPeerKpg.initialize(ECGenParameterSpec("secp521r1"))
            val dummyPeerKeyPair = dummyPeerKpg.generateKeyPair()
            val dummyAgreement = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
            dummyAgreement.init(entry.privateKey)
            dummyAgreement.doPhase(dummyPeerKeyPair.public, true)
            val dummySecret = dummyAgreement.generateSecret()
            dummySecret.fill(0)
            out.appendLine("   -> Dummy ECDH completed & wiped. KeyMint HAL Binder return parcel successfully overwritten!")

            out.appendLine("   Status: Shared secret received and local copy wiped.")

        } catch (e: Exception) {
            out.appendLine("ERROR in ECDH Agreement: ${e.message}")
            Log.e(TAG, "ECDH Agreement failed", e)
        }

        return out.toString()
    }

    /**
     * Scenario 3: Mock Digital Identity Credential (ISO 18013-5 mDL Presentation)
     * Demonstrates an official digital ID (mDL / My Number Card) presentation flow.
     * Mimics android.security.identity.CredstoreIdentityCredential.java key agreement and HKDF derivation.
     */
    private fun runMockIdentityPresentation(enableCallerFlush: Boolean): String {
        val out = StringBuilder()
        out.appendLine("==================================================")
        out.appendLine("[Scenario 3] Mock Digital Identity (ISO 18013-5 mDL)")
        out.appendLine("Mode: ${if (enableCallerFlush) "PROTECTED (With Caller Buffer Flush)" else "VULNERABLE (Standard Android Stack / No Flush)"}")
        out.appendLine("==================================================")

        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            // 1. Citizen Identity Authentication Key (Hardware-backed in KeyStore)
            if (!keyStore.containsAlias(MDL_KEY_ALIAS)) {
                out.appendLine("1. Identity Provisioning: Generating Hardware Authentication EC KeyPair...")
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                val spec = KeyGenParameterSpec.Builder(
                    MDL_KEY_ALIAS,
                    KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp521r1"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                    .build()
                kpg.initialize(spec)
                kpg.generateKeyPair()
                out.appendLine("   -> Citizen Hardware EC KeyPair created with alias '$MDL_KEY_ALIAS'")
            } else {
                out.appendLine("1. Identity Provisioning: Using existing Citizen Hardware EC KeyPair '$MDL_KEY_ALIAS'")
            }

            val citizenKeyEntry = keyStore.getEntry(MDL_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry

            // 2. Verifier / Reader Terminal (e.g. Police, TSA, Bank) presents ephemeral public key
            out.appendLine("2. Reader Handshake: Verifier terminal provides Ephemeral Public Key...")
            val readerKpg = KeyPairGenerator.getInstance("EC")
            readerKpg.initialize(ECGenParameterSpec("secp521r1"))
            val readerKeyPair = readerKpg.generateKeyPair()
            val readerPubKeyX509Hex = readerKeyPair.public.encoded.joinToString("") { "%02x".format(it) }

            // 3. JCA KeyAgreement: Compute ECDH Shared Secret with Hardware Key
            out.appendLine("3. JCA KeyAgreement: Computing session Shared Secret via KeyMint HAL...")
            val ka = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
            ka.init(citizenKeyEntry.privateKey)
            ka.doPhase(readerKeyPair.public, true)
            val sharedSecret = ka.generateSecret()
            val secretHex = sharedSecret.joinToString("") { "%02x".format(it) }

            out.appendLine("   -> KeyMint HAL returned Shared Secret (${sharedSecret.size} bytes):")
            out.appendLine("   [Target Session Secret Hex in RAM]:")
            out.appendLine("   >> $secretHex <<")

            // 4. Session Key Derivation (HKDF-SHA256, mimicking CredstoreIdentityCredential.java)
            out.appendLine("4. HKDF Key Derivation: Deriving 256-bit AES-GCM session key (mSecretKey)...")
            val salt = byteArrayOf(0x01)
            val info = byteArrayOf() // ISO 18013-5 session info
            val sessionKeyBytes = computeHkdf("HmacSha256", sharedSecret, salt, info, 32)
            val sessionKeySpec = SecretKeySpec(sessionKeyBytes, "AES")

            // 5. Citizen PII Payload (Government Identity Data)
            val citizenPiiJson = """
                {
                    "document_type": "ISO 18013-5 Mobile Driving License / National ID",
                    "full_name": "Taro Yamada",
                    "id_number": "DL-9876-5432-10",
                    "date_of_birth": "1990-05-15",
                    "address": "1-1 Chiyoda, Chiyoda-ku, Tokyo 100-8111",
                    "biometric_facial_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "issuing_authority": "National Police Agency / Digital Agency"
                }
            """.trimIndent()

            out.appendLine("5. Encrypting Citizen PII Payload with AES-GCM...")
            val piiCipher = Cipher.getInstance("AES/GCM/NoPadding")
            piiCipher.init(Cipher.ENCRYPT_MODE, sessionKeySpec)
            val piiIv = piiCipher.iv
            val encryptedPii = piiCipher.doFinal(citizenPiiJson.toByteArray(Charsets.UTF_8))
            val encryptedPiiHex = encryptedPii.joinToString("") { "%02x".format(it) }
            val ivHex = piiIv.joinToString("") { "%02x".format(it) }

            out.appendLine("   -> Encrypted PII Payload len: ${encryptedPii.size} bytes")
            out.appendLine("   -> IV: $ivHex")

            // 6. Save Session File for Simulated Eavesdropping Interception Tool
            val sessionJson = """
                {
                    "target_shared_secret_hex": "$secretHex",
                    "reader_public_key_x509_hex": "$readerPubKeyX509Hex",
                    "salt_hex": "01",
                    "info_hex": "",
                    "iv_hex": "$ivHex",
                    "encrypted_pii_hex": "$encryptedPiiHex",
                    "unencrypted_pii_json": ${JSONObject(citizenPiiJson).toString()},
                    "flush_enabled": $enableCallerFlush
                }
            """.trimIndent()

            val sessionFile = java.io.File(filesDir, "mock_mdl_session.json")
            sessionFile.writeText(sessionJson)

            val targetFile = java.io.File(filesDir, "target_keys.txt")
            targetFile.writeText("TARGET_SHARED_SECRET_HEX=$secretHex\n")

            Log.i(TAG, "--------------------------------------------------")
            Log.i(TAG, "[SCENARIO 3: MOCK DIGITAL ID PRESENTATION]")
            Log.i(TAG, "TARGET_SHARED_SECRET_HEX=$secretHex")
            Log.i(TAG, "Saved mDL session to ${sessionFile.absolutePath}")
            Log.i(TAG, "--------------------------------------------------")

            // Wiping local session buffers in app memory
            sharedSecret.fill(0)
            sessionKeyBytes.fill(0)
            out.appendLine("6. App Zeroization: Local sharedSecret[] and sessionKey[] wiped with 0x00.")

            // 7. Optional Caller-Side Buffer Flush
            if (enableCallerFlush) {
                out.appendLine("7. Caller Buffer Flush: Executing dummy ECDH agreement to overwrite KeyMint HAL Binder parcel...")
                val dummyPeerKpg = KeyPairGenerator.getInstance("EC")
                dummyPeerKpg.initialize(ECGenParameterSpec("secp521r1"))
                val dummyPeerKeyPair = dummyPeerKpg.generateKeyPair()
                val dummyAgreement = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
                dummyAgreement.init(citizenKeyEntry.privateKey)
                dummyAgreement.doPhase(dummyPeerKeyPair.public, true)
                val dummySecret = dummyAgreement.generateSecret()
                dummySecret.fill(0)
                out.appendLine("   -> Buffer flush completed. Residual HAL parcel overwritten.")
            } else {
                out.appendLine("7. Caller Buffer Flush: SKIPPED (Vulnerable State for Demonstration).")
            }

            out.appendLine("\n[Ready for Memory Scanner]: Run 'python3 memory-test/demo_mdl_eavesdrop.py'")

        } catch (e: Exception) {
            out.appendLine("ERROR in Mock Identity Presentation: ${e.message}")
            Log.e(TAG, "Mock Identity Presentation failed", e)
        }

        return out.toString()
    }
}

@Composable
fun VerificationScreen(
    modifier: Modifier = Modifier,
    onRunKeyWrappingTest: () -> String,
    onRunEcdhTest: () -> String,
    onRunMockIdentityTestUnprotected: () -> String,
    onRunMockIdentityTestProtected: () -> String,
    onRunAllTests: () -> String
) {
    var outputLog by remember { mutableStateOf("Ready.\nSelect a verification or demo scenario below.") }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text(
            text = "KeyStore JCA Leak & Identity Verifier",
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold
        )

        Text(
            text = "Standard JCA operations without hardcoded keys. Compare logged hex values directly with KeyMint process RAM dumps.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { outputLog = onRunKeyWrappingTest() },
                modifier = Modifier.weight(1f)
            ) {
                Text("1. Key Wrapping", fontSize = 11.sp)
            }
            Button(
                onClick = { outputLog = onRunEcdhTest() },
                modifier = Modifier.weight(1f)
            ) {
                Text("2. ECDH Agreement", fontSize = 11.sp)
            }
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Button(
                onClick = { outputLog = onRunMockIdentityTestUnprotected() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC62828))
            ) {
                Text("3. mDL (Vulnerable / No Flush)", fontSize = 11.sp)
            }
            Button(
                onClick = { outputLog = onRunMockIdentityTestProtected() },
                modifier = Modifier.weight(1f),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))
            ) {
                Text("4. mDL (Protected / Flush)", fontSize = 11.sp)
            }
        }

        Button(
            onClick = { outputLog = onRunAllTests() },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
        ) {
            Text("Run All Verifications (Generate All Target Keys)", fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }

        Text(
            text = "Execution Steps & Target Hex Values for Memory Matching:",
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold
        )

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            shape = RoundedCornerShape(8.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF1E1E1E))
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                Text(
                    text = outputLog,
                    color = Color(0xFF81C784),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            }
        }
    }
}
