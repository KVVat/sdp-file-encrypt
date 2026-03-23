package com.android.niapsec.realworld.db

import androidx.room.Entity
import androidx.room.PrimaryKey
import java.util.UUID

@Entity(tableName = "mission_briefing")
data class MissionBriefing(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val title: String,
    val timestamp: Long,
    val isSweeped: Boolean,
    val textFilePath: String,
    val imageFilePath: String? = null
)
