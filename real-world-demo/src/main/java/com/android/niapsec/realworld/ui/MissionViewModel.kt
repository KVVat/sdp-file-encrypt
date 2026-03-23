package com.android.niapsec.realworld.ui

import android.app.Application
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.android.niapsec.encryption.api.EncryptionManager
import com.android.niapsec.encryption.api.KeyProviderType
import com.android.niapsec.realworld.db.MissionBriefing
import com.android.niapsec.realworld.db.MissionDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.UUID

class MissionViewModel(application: Application) : AndroidViewModel(application) {

    private val missionDao = MissionDatabase.getDatabase(application).missionDao()
    
    // Using HYBRID by default as specified in AGENTS.md for the "gold standard"
    private val encryptionManager = EncryptionManager(
        context = application,
        masterKeyUri = "android-keystore://agency_master_key",
        providerType = KeyProviderType.HYBRID,
        unlockedDeviceRequired = true // Ensure decryption fails when locked in the future
    )

    private val _missions = MutableStateFlow<List<MissionBriefing>>(emptyList())
    val missions: StateFlow<List<MissionBriefing>> = _missions.asStateFlow()

    // Hacking state
    private val _isHackingActive = MutableStateFlow(false)
    val isHackingActive: StateFlow<Boolean> = _isHackingActive.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    fun clearError() {
        _errorMessage.value = null
    }

    init {
        loadMissions()
    }

    private fun loadMissions() {
        viewModelScope.launch(Dispatchers.IO) {
            val list = missionDao.getAllMissions()
            _missions.value = list
        }
    }

    fun simulateIncomingTransmission() {
        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            val missionsDir = File(context.filesDir, "missions")
            if (!missionsDir.exists()) {
                missionsDir.mkdirs()
            }

            // 1. Create a dummy plaintext mission file
            val uuid = UUID.randomUUID().toString()
            val dummyText = """
# 🚨 TOP SECRET DIRECTIVE [$uuid]

🛡️ **Agent**, proceed to coordinates `34.0522, -118.2437` immediately.
Ensure no tails.

![Agent Briefing](secret_agent_start)

## 📎 [PRIORITY ATTACHMENT]
**Enemy Terminal Access Code**: `EAGLE-99`
⚠️ _Use strictly when the target is rebooted (DirectBoot scenario)._
""".trimIndent()
            val sourceFile = File(missionsDir, "temp_$uuid.txt")
            sourceFile.writeText(dummyText)

            // 2. Encrypt the file using EncryptionManager
            val destFile = File(missionsDir, "directive_$uuid.enc")
            try {
                encryptionManager.encryptFile(sourceFile, destFile, deleteOriginal = true)
                Log.d("MissionViewModel", "File encrypted successfully to ${destFile.absolutePath}")

                // 3. Save metadata to Room database
                val newMission = MissionBriefing(
                    title = "Directive ${uuid.substring(0, 8).uppercase()}",
                    timestamp = System.currentTimeMillis(),
                    isSweeped = false,
                    textFilePath = destFile.absolutePath
                )
                missionDao.insertMission(newMission)
                
                // Refresh list
                loadMissions()
            } catch (e: Exception) {
                Log.e("MissionViewModel", "Failed to encrypt incoming transmission", e)
                _errorMessage.value = "受信失敗: セキュアな画面ロック（PIN/パスワード）が設定されていない、または暗号化エラーです。\nエラー: ${e.message}"
            }
        }
    }

    fun hackEnemyTerminal(password: String, onResult: (Boolean, String) -> Unit) {
        if (password != "EAGLE-99") {
            onResult(false, "ACCESS DENIED: Invalid Intel Code.")
            return
        }

        if (_isHackingActive.value) return
        _isHackingActive.value = true

        viewModelScope.launch(Dispatchers.IO) {
            val context = getApplication<Application>()
            val missionsDir = File(context.filesDir, "missions")
            if (!missionsDir.exists()) {
                missionsDir.mkdirs()
            }

            try {
                // Simulate batch downloading of 10 incoming intel files
                for (i in 1..10) {
                    val intelId = UUID.randomUUID().toString().substring(0, 6)
                    val dummyText = "INTERCEPTED COMMUNICATION #$i [$intelId]\n\nEnemy movement detected in Sector $i.\nSecure the payload."
                    
                    val sourceFile = File(missionsDir, "batch_$intelId.txt")
                    sourceFile.writeText(dummyText)

                    val destFile = File(missionsDir, "intel_$intelId.enc")
                    
                    encryptionManager.encryptFile(sourceFile, destFile, deleteOriginal = true)
                    
                    val newMission = MissionBriefing(
                        title = "Intercepted Intel #$i",
                        timestamp = System.currentTimeMillis() + (i * 1000), // Offset slightly to preserve order
                        isSweeped = false,
                        textFilePath = destFile.absolutePath
                    )
                    missionDao.insertMission(newMission)
                }
                loadMissions()
                withContext(Dispatchers.Main) {
                    onResult(true, "ACCESS GRANTED: 10 Intel Files Decrypted and Downloaded.")
                }
            } catch (e: Exception) {
                Log.e("MissionViewModel", "Failed batch hack encryption", e)
                withContext(Dispatchers.Main) {
                    onResult(false, "ERROR: Connection Lost or Encryption Failure.")
                }
            } finally {
                _isHackingActive.value = false
            }
        }
    }

    /**
     * Tries to decrypt the specified encrypted file and return its textual content.
     */
    suspend fun decryptMissionContent(encryptedFilePath: String): String? {
        return withContext(Dispatchers.IO) {
            val encFile = File(encryptedFilePath)
            if (!encFile.exists()) return@withContext null

            try {
                encryptionManager.decryptFromFile(encFile).use { input ->
                    input.bufferedReader().readText()
                }
            } catch (e: Exception) {
                Log.e("MissionViewModel", "Failed to decrypt mission file", e)
                "ERROR: Decryption Failed. Check device lock state or key validity."
            }
        }
    }
    
    suspend fun getRawEncryptedBytesHex(encryptedFilePath: String): String {
         return withContext(Dispatchers.IO) {
             val file = File(encryptedFilePath)
             if(!file.exists()) return@withContext "FILE_NOT_FOUND"
             
             // Read the entire file to avoid shortening the ciphertext
             val bytes = file.readBytes()
             formatHexDump(bytes)
         }
    }

    private fun formatHexDump(bytes: ByteArray): String {
        val builder = java.lang.StringBuilder()
        for (i in bytes.indices step 8) {
            val chunkLength = minOf(8, bytes.size - i)
            val chunk = bytes.copyOfRange(i, i + chunkLength)
            
            // Offset (4 hex chars = 2 bytes)
            builder.append(String.format("%04X  ", i))
            
            // Hex string (8 bytes)
            for (j in 0 until 8) {
                if (j < chunkLength) {
                    builder.append(String.format("%02X ", chunk[j]))
                } else {
                    builder.append("   ")
                }
            }
            
            builder.append(" |")
            
            // ASCII string
            for (j in 0 until chunkLength) {
                val c = chunk[j].toInt()
                if (c in 32..126) {
                    builder.append(c.toChar())
                } else {
                    builder.append('.')
                }
            }
            builder.append("|\n")
        }
        return builder.toString()
    }

    override fun onCleared() {
        super.onCleared()
        // Clean up EncryptionProvider resources if needed
    }
}
