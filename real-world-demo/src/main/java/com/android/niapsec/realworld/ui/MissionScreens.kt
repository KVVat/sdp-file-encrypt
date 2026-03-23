package com.android.niapsec.realworld.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.viewinterop.AndroidView
import android.widget.TextView
import io.noties.markwon.Markwon
import io.noties.markwon.image.ImagesPlugin
import android.graphics.BitmapFactory
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.util.Base64
import java.io.ByteArrayOutputStream
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.ArrowBack
import com.android.niapsec.realworld.db.MissionBriefing
import java.text.SimpleDateFormat
import java.util.*

@Composable
fun MainNavigation(viewModel: MissionViewModel) {
    var selectedMission: MissionBriefing? by remember { mutableStateOf(null) }

    if (selectedMission == null) {
        DashboardScreen(
            viewModel = viewModel,
            onMissionClick = { selectedMission = it }
        )
    } else {
        DetailScreen(
            viewModel = viewModel,
            mission = selectedMission!!,
            onBack = { selectedMission = null }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: MissionViewModel,
    onMissionClick: (MissionBriefing) -> Unit
) {
    val isHackingActive by viewModel.isHackingActive.collectAsState()
    val errorMessage by viewModel.errorMessage.collectAsState()
    val missions by viewModel.missions.collectAsState()
    var showHackingDialog by remember { mutableStateOf(false) }
    var hackMessage by remember { mutableStateOf<String?>(null) }
    var showFutureToast by remember { mutableStateOf<String?>(null) }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Agency Network", fontWeight = FontWeight.Black) },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                )
            },
            floatingActionButton = {
                FloatingActionButton(onClick = { viewModel.simulateIncomingTransmission() }) {
                    Text("+") // Simulate receiving a mission
                }
            }
        ) { paddingValues ->
            Column(modifier = Modifier.padding(paddingValues).padding(horizontal = 16.dp)) {

                // Game-like action buttons
                Row(
                    modifier = Modifier.fillMaxWidth().padding(vertical = 16.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Button(
                        onClick = { showFutureToast = "ZipBackup & Argon2 implementation pending." },
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary)
                    ) {
                        Text("バックアップ")
                    }
                    Button(
                        onClick = { showHackingDialog = true },
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary)
                    ) {
                        Text("接続 (Hack)")
                    }
                    Button(
                        onClick = { showFutureToast = "Key destruction sequence implementation pending." },
                        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                    ) {
                        Text("自爆")
                    }
                }

                if (isHackingActive) {
                    LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp))
                    Text("Decrypting & Downloading...", style = MaterialTheme.typography.labelSmall, modifier = Modifier.align(Alignment.CenterHorizontally).padding(bottom = 8.dp))
                }
                hackMessage?.let { msg ->
                    Text(msg, color = if (msg.contains("ERROR") || msg.contains("DENIED")) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(bottom = 16.dp))
                }

                if (missions.isEmpty()) {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        Text("No mission directives found. Waiting for transmission...")
                    }
                } else {
                    LazyColumn {
                        items(missions) { mission ->
                            MissionItem(mission = mission, onClick = { onMissionClick(mission) })
                            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                        }
                    }
                }
            }
        }

        if (showFutureToast != null) {
            AlertDialog(
                onDismissRequest = { showFutureToast = null },
                title = { Text("Future Update") },
                text = { Text(showFutureToast ?: "") },
                confirmButton = {
                    TextButton(onClick = { showFutureToast = null }) { Text("OK") }
                }
            )
        }

        if (errorMessage != null) {
            AlertDialog(
                onDismissRequest = { viewModel.clearError() },
                icon = { Icon(Icons.Filled.Warning, contentDescription = "Error") },
                title = { Text("Transmission Failed") },
                text = { Text(errorMessage ?: "Unknown error.") },
                confirmButton = {
                    TextButton(onClick = { viewModel.clearError() }) { Text("OK") }
                }
            )
        }

        if (showHackingDialog) {
            var passwordInput by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = { showHackingDialog = false },
                icon = { Icon(Icons.Filled.Warning, contentDescription = "Warning") },
                title = { Text("Terminal Access") },
                text = {
                    Column {
                        Text("Enter the confiscated Intel Code to initiate batch download:")
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = passwordInput,
                            onValueChange = { passwordInput = it },
                            label = { Text("Intel Code") },
                            singleLine = true
                        )
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        showHackingDialog = false
                        hackMessage = "Initiating..."
                        viewModel.hackEnemyTerminal(passwordInput) { success, msg ->
                            hackMessage = msg
                        }
                    }) {
                        Text("Execute")
                    }
                },
                dismissButton = {
                    TextButton(onClick = { showHackingDialog = false }) { Text("Cancel") }
                }
            )
        }
    }
}

@Composable
fun MissionItem(mission: MissionBriefing, onClick: () -> Unit) {
    val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
    val dateString = dateFormat.format(Date(mission.timestamp))

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(8.dp)
    ) {
        Text(text = mission.title, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
        Row(
            modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(text = "Status: ${if (mission.isSweeped) "Sweeped" else "Active"}", style = MaterialTheme.typography.bodySmall)
            Text(text = dateString, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(
    viewModel: MissionViewModel,
    mission: MissionBriefing,
    onBack: () -> Unit
) {
    var selectedTabIndex by rememberSaveable { mutableStateOf(0) }
    var plainTextContent by remember { mutableStateOf("Decrypting...") }
    var cipherTextContent by remember { mutableStateOf("Reading raw bits...") }
    val context = LocalContext.current
    val markwon = remember {
        Markwon.builder(context)
            .usePlugin(ImagesPlugin.create())
            .build()
    }

    LaunchedEffect(mission) {
        launch(kotlinx.coroutines.Dispatchers.IO) {
            val rawText = viewModel.decryptMissionContent(mission.textFilePath) ?: "Error: File content not found."
            val regex = "!\\[(.*?)\\]\\((.*?)\\)".toRegex()
            var processedText = rawText
            regex.findAll(rawText).forEach { matchResult ->
                val alt = matchResult.groupValues[1]
                val resName = matchResult.groupValues[2]
                val resId = context.resources.getIdentifier(resName, "drawable", context.packageName)
                if (resId != 0) {
                    try {
                        val bitmap = BitmapFactory.decodeResource(context.resources, resId)
                        val baos = ByteArrayOutputStream()
                        bitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 80, baos)
                        val b64 = Base64.encodeToString(baos.toByteArray(), Base64.NO_WRAP)
                        val replacement = "![${alt}](data:image/jpeg;base64,$b64)"
                        processedText = processedText.replace(matchResult.value, replacement)
                    } catch (e: Exception) {}
                }
            }
            plainTextContent = processedText
        }
        launch(kotlinx.coroutines.Dispatchers.IO) {
            cipherTextContent = viewModel.getRawEncryptedBytesHex(mission.textFilePath)
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("Directive Details", fontWeight = FontWeight.Bold) },
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(Icons.Filled.ArrowBack, contentDescription = "Back")
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer,
                        titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                )
            }
        ) { paddingValues ->
            Column(modifier = Modifier.padding(paddingValues).padding(16.dp)) {
                
                Text(text = "Title: ${mission.title}", fontWeight = FontWeight.Medium, style = MaterialTheme.typography.bodyLarge)
                Spacer(modifier = Modifier.height(16.dp))
            
                androidx.compose.material3.TabRow(selectedTabIndex = selectedTabIndex) {
                    androidx.compose.material3.Tab(
                        selected = selectedTabIndex == 0,
                        onClick = { selectedTabIndex = 0 },
                        text = { Text("Plaintext") }
                    )
                    androidx.compose.material3.Tab(
                        selected = selectedTabIndex == 1,
                        onClick = { selectedTabIndex = 1 },
                        text = { Text("Ciphertext") }
                    )
                }

            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(16.dp))

            Surface(
                modifier = Modifier.fillMaxWidth().weight(1f),
                color = if (selectedTabIndex == 1) androidx.compose.ui.graphics.Color(0xFF0F2016) else androidx.compose.ui.graphics.Color(0xFF1E1E1E),
                shape = MaterialTheme.shapes.small
            ) {
                LazyColumn(modifier = Modifier.padding(16.dp)) {
                    item {
                        if (selectedTabIndex == 1) {
                            Text(
                                text = cipherTextContent,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                color = androidx.compose.ui.graphics.Color(0xFF00FF41),
                                style = MaterialTheme.typography.bodySmall
                            )
                        } else {
                            AndroidView(
                                factory = { ctx ->
                                    TextView(ctx).apply {
                                        setTextColor(if (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK == android.content.res.Configuration.UI_MODE_NIGHT_YES) android.graphics.Color.WHITE else android.graphics.Color.BLACK)
                                    }
                                },
                                update = { view ->
                                    markwon.setMarkdown(view, plainTextContent)
                                }
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            if (mission.imageFilePath != null) {
                Text(text = "Attached Image: ${mission.imageFilePath}", fontStyle = androidx.compose.ui.text.font.FontStyle.Italic)
            }
        }
        }
    }
}
