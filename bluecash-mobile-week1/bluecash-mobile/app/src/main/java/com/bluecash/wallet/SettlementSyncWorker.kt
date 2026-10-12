package com.bluecash.wallet

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequest
import androidx.work.PeriodicWorkRequest
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.BackoffPolicy
import com.bluecash.wallet.core.MintApiException
import java.util.concurrent.TimeUnit

/** Uploads merchant receipts and refreshes revocations whenever the phone gets connectivity back. */
class SettlementSyncWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {
    override fun doWork(): Result = try {
        AppContainer.wallet.sync(AppContainer.mintApi())
        AppContainer.refreshState()
        Result.success()
    } catch (e: MintApiException) {
        Result.retry()
    } catch (e: Exception) {
        Result.failure()
    }
}

object SyncScheduler {
    private fun constraints(): Constraints {
        // The simulated mint lives on the phone, so it needs no network; a real server does.
        val b = Constraints.Builder()
        if (AppContainer.serverUrl.isNotBlank()) b.setRequiredNetworkType(NetworkType.CONNECTED)
        return b.build()
    }

    fun schedulePeriodic(ctx: Context) {
        val req = PeriodicWorkRequest.Builder(SettlementSyncWorker::class.java, 15, TimeUnit.MINUTES)
            .setConstraints(constraints()).build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("settlement-periodic", ExistingPeriodicWorkPolicy.UPDATE, req)
    }

    fun syncNow(ctx: Context) {
        val req = OneTimeWorkRequest.Builder(SettlementSyncWorker::class.java)
            .setConstraints(constraints())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS).build()
        WorkManager.getInstance(ctx).enqueueUniqueWork("settlement-now", ExistingWorkPolicy.REPLACE, req)
    }
}
