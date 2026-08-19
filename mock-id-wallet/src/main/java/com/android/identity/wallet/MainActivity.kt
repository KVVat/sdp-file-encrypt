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
package com.android.identity.wallet

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONObject
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class MainActivity : ComponentActivity() {

    companion object {
        const val TAG = "DigitalIdWallet"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val AUTH_KEY_ALIAS = "mock_identity_auth_p521_key"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    WalletHomeScreen(
                        modifier = Modifier.padding(innerPadding),
                        onPresentId = { presentIdentityCredential() }
                    )
                }
            }
        }
    }

    /**
     * Helper: RFC 5869 HKDF Key Derivation (Extract + Expand)
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
     * Executes the standard ISO 18013-5 (mDL) Presentation Workflow.
     * Mimics android.security.identity.CredstoreIdentityCredential presentation.
     */
    private fun presentIdentityCredential(): String {
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

            // 1. Ensure Hardware EC Key in KeyStore
            if (!keyStore.containsAlias(AUTH_KEY_ALIAS)) {
                val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
                val spec = KeyGenParameterSpec.Builder(
                    AUTH_KEY_ALIAS,
                    KeyProperties.PURPOSE_AGREE_KEY
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp521r1"))
                    .setDigests(KeyProperties.DIGEST_NONE)
                    .build()
                kpg.initialize(spec)
                kpg.generateKeyPair()
            }

            val citizenKeyEntry = keyStore.getEntry(AUTH_KEY_ALIAS, null) as KeyStore.PrivateKeyEntry

            // 2. Verifier / Terminal Ephemeral Key
            val readerKpg = KeyPairGenerator.getInstance("EC")
            readerKpg.initialize(ECGenParameterSpec("secp521r1"))
            val readerKeyPair = readerKpg.generateKeyPair()
            val readerPubKeyX509Hex = readerKeyPair.public.encoded.joinToString("") { "%02x".format(it) }

            // 3. JCA KeyAgreement: Compute ECDH Shared Secret via KeyMint HAL
            val ka = KeyAgreement.getInstance("ECDH", ANDROID_KEYSTORE)
            ka.init(citizenKeyEntry.privateKey)
            ka.doPhase(readerKeyPair.public, true)
            val sharedSecret = ka.generateSecret()
            val secretHex = sharedSecret.joinToString("") { "%02x".format(it) }

            // 4. Session Key Derivation (HKDF-SHA256)
            val salt = byteArrayOf(0x01)
            val info = byteArrayOf()
            val sessionKeyBytes = computeHkdf("HmacSha256", sharedSecret, salt, info, 32)
            val sessionKeySpec = SecretKeySpec(sessionKeyBytes, "AES")

            // 5. Citizen PII Payload (Official National ID & Driving License Data)
            val citizenPiiJson = """
                {
                    "document_type": "ISO 18013-5 Mobile Driving License / National ID",
                    "full_name": "Taro Yamada (山田 太郎)",
                    "id_number": "DL-9876-5432-10",
                    "my_number": "1234-5678-9012",
                    "date_of_birth": "1990-05-15",
                    "address": "1-1 Chiyoda, Chiyoda-ku, Tokyo 100-8111",
                    "biometric_facial_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "issuing_authority": "Digital Agency & National Police Agency of Japan",
                    "verification_status": "AUTHENTIC_GOVERNMENT_ISSUED"
                }
            """.trimIndent()

            // 6. Encrypt with AES-GCM
            val piiCipher = Cipher.getInstance("AES/GCM/NoPadding")
            piiCipher.init(Cipher.ENCRYPT_MODE, sessionKeySpec)
            val piiIv = piiCipher.iv
            val encryptedPii = piiCipher.doFinal(citizenPiiJson.toByteArray(Charsets.UTF_8))
            val encryptedPiiHex = encryptedPii.joinToString("") { "%02x".format(it) }
            val ivHex = piiIv.joinToString("") { "%02x".format(it) }

            // 7. Save Session File for Interception / Verification Demo
            val sessionJson = """
                {
                    "target_shared_secret_hex": "$secretHex",
                    "reader_public_key_x509_hex": "$readerPubKeyX509Hex",
                    "salt_hex": "01",
                    "info_hex": "",
                    "iv_hex": "$ivHex",
                    "encrypted_pii_hex": "$encryptedPiiHex",
                    "unencrypted_pii_json": ${JSONObject(citizenPiiJson).toString()},
                    "flush_enabled": false
                }
            """.trimIndent()

            val sessionFile = java.io.File(filesDir, "mock_mdl_session.json")
            sessionFile.writeText(sessionJson)

            val targetFile = java.io.File(filesDir, "target_keys.txt")
            targetFile.writeText("TARGET_SHARED_SECRET_HEX=$secretHex\n")

            Log.i(TAG, "[MOCK IDENTITY WALLET] Presented ID. Target Secret: $secretHex")

            // Local wipe
            sharedSecret.fill(0)
            sessionKeyBytes.fill(0)

            return "✓ ID presented successfully via ISO 18013-5 handshake.\nEncrypted BLE/NFC session payload transmitted."
        } catch (e: Exception) {
            Log.e(TAG, "Presentation failed", e)
            return "ERROR: ${e.message}"
        }
    }
}

@Composable
fun WalletHomeScreen(
    modifier: Modifier = Modifier,
    onPresentId: () -> String
) {
    var statusText by remember { mutableStateOf("Hold your phone near a contactless reader to present your digital ID.") }
    var isPresenting by remember { mutableStateOf(false) }

    val infiniteTransition = rememberInfiniteTransition(label = "nfc_pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse"
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color(0xFFF8FAFC)) // Clean, modern light slate background
            .padding(20.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(18.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(modifier = Modifier.height(10.dp))

        // Wallet Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "Google Wallet",
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFF0F172A)
                )
                Text(
                    text = "Digital ID & Travel Credentials",
                    style = MaterialTheme.typography.bodyMedium,
                    color = Color(0xFF64748B)
                )
            }
            Surface(
                shape = CircleShape,
                color = Color(0xFFE2E8F0),
                modifier = Modifier.size(36.dp)
            ) {
                Box(contentAlignment = Alignment.Center) {
                    Text("👤", fontSize = 18.sp)
                }
            }
        }

        // Visual Digital ID Card (Google Wallet Style)
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(230.dp),
            shape = RoundedCornerShape(20.dp),
            elevation = CardDefaults.cardElevation(defaultElevation = 6.dp)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.linearGradient(
                            colors = listOf(
                                Color(0xFF1E3A8A), // Elegant Navy Blue
                                Color(0xFF0F172A)  // Deep Midnight
                            )
                        )
                    )
                    .padding(20.dp)
            ) {
                Column(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.SpaceBetween
                ) {
                    // Card Top Row
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text("🇯🇵 ", fontSize = 18.sp)
                            Text(
                                "JAPAN DRIVER'S LICENSE / マイナンバー",
                                color = Color(0xFFF1F5F9),
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        Text(
                            "((( • )))",
                            color = Color(0xFF38BDF8),
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    // Card Middle Row: Chip, Photo & Name
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(14.dp)
                    ) {
                        // Gold EMV Chip
                        Box(
                            modifier = Modifier
                                .size(44.dp, 34.dp)
                                .clip(RoundedCornerShape(6.dp))
                                .background(Color(0xFFFACC15))
                                .border(1.dp, Color(0xFFCA8A04), RoundedCornerShape(6.dp))
                        )

                        // Citizen Photo Box
                        Box(
                            modifier = Modifier
                                .size(52.dp, 60.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(Color(0xFF334155)),
                            contentAlignment = Alignment.Center
                        ) {
                            Text("👤", fontSize = 28.sp)
                        }

                        // Citizen Name & Document Number
                        Column {
                            Text(
                                text = "TARO YAMADA",
                                color = Color.White,
                                fontSize = 17.sp,
                                fontWeight = FontWeight.ExtraBold
                            )
                            Text(
                                text = "山田 太郎",
                                color = Color(0xFF94A3B8),
                                fontSize = 13.sp
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = "DL-9876-5432-10",
                                color = Color(0xFF38BDF8),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                        }
                    }

                    // Card Bottom Row
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.Bottom
                    ) {
                        Column {
                            Text("DOB: 1990/05/15", color = Color(0xFFCBD5E1), fontSize = 11.sp)
                            Text("EXP: 2030/05/15", color = Color(0xFFCBD5E1), fontSize = 11.sp)
                        }
                        Text(
                            "🏛️ DIGITAL AGENCY",
                            color = Color(0xFF94A3B8),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        // Clean Explanation Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFF1F5F9))
        ) {
            Column(
                modifier = Modifier.padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Text(
                    text = "🔒 Platform Security Architecture",
                    color = Color(0xFF0F172A),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "This digital credential is saved and presented using the same AndroidKeyStore hardware-backed key agreement (ECDH P-521) and ISO 18013-5 Identity Credential APIs used in Google Wallet.",
                    color = Color(0xFF475569),
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        // Main Action Button: Hold Near Reader (かざす)
        Button(
            onClick = {
                isPresenting = true
                statusText = onPresentId()
                isPresenting = false
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(58.dp)
                .scale(if (isPresenting) pulseScale else 1f),
            shape = RoundedCornerShape(14.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = Color(0xFF0284C7) // Friendly, bright Google Blue
            ),
            elevation = ButtonDefaults.buttonElevation(defaultElevation = 4.dp)
        ) {
            Text(
                text = "📲 Hold Near Reader to Present (かざす)",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }

        // Status Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFFFFFFFF)),
            elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
        ) {
            Column(modifier = Modifier.padding(14.dp)) {
                Text(
                    text = "Reader Status",
                    color = Color(0xFF64748B),
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = statusText,
                    color = Color(0xFF0F172A),
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            }
        }
    }
}
