package com.android.niapsec.realworld.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query


@Dao
interface MissionDao {
    @Query("SELECT * FROM mission_briefing ORDER BY timestamp DESC")
    fun getAllMissions(): List<MissionBriefing>

    @Query("SELECT * FROM mission_briefing WHERE id = :missionId")
    fun getMissionById(missionId: String): MissionBriefing?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insertMission(mission: MissionBriefing)

    @Query("DELETE FROM mission_briefing")
    fun deleteAllMissions()
}
