package com.android.niapsec.realworld.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [MissionBriefing::class], version = 1, exportSchema = false)
abstract class MissionDatabase : RoomDatabase() {

    abstract fun missionDao(): MissionDao

    companion object {
        @Volatile
        private var INSTANCE: MissionDatabase? = null

        fun getDatabase(context: Context): MissionDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    MissionDatabase::class.java,
                    "agency_missions.db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
