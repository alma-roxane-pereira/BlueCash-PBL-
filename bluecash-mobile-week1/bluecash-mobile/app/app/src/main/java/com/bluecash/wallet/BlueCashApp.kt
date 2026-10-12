package com.bluecash.wallet

import android.app.Application

class BlueCashApp : Application() {
    override fun onCreate() {
        super.onCreate()
        AppContainer.init(this)
        SyncScheduler.schedulePeriodic(this)
        // Play Integrity check at app start (skipped while AppConfig.PLAY_INTEGRITY_CLOUD_PROJECT is 0).
        IntegrityChecker.check(this) { state, _ -> AppContainer.integrity = state }
        AppContainer.refreshAsync()
    }
}
