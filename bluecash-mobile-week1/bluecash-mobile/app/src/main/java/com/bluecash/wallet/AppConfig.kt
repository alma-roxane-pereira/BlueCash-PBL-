package com.bluecash.wallet

object AppConfig {
    /**
     * Google Cloud project number for the Play Integrity API. Leave 0 until you've created a
     * Cloud project and linked it in the Play Console; while 0, integrity checks are skipped
     * (shown as "not configured") and never block anything.
     */
    const val PLAY_INTEGRITY_CLOUD_PROJECT = 0L
}
