package com.whitescan.app

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

// Foreground service that keeps scans alive when the app is backgrounded.
// The ScanViewModel lives in the Activity but the service holds a wakelock-
// equivalent via the foreground notification so Android cannot kill the process.
//
// The service is intentionally thin: it just shows the notification and lets the
// Activity/ViewModel own the scan state. When the Activity binds it observes the
// same ViewModel; when it unbinds the notification keeps the process alive.
class ScanService : Service() {

    inner class LocalBinder : Binder() {
        fun getService(): ScanService = this@ScanService
    }

    private val binder = LocalBinder()

    override fun onBind(intent: Intent): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startForegroundScan(
                intent.getStringExtra(EXTRA_LABEL) ?: "Scanning…",
                intent.getIntExtra(EXTRA_FOUND, 0),
            )
            ACTION_UPDATE -> updateNotification(
                intent.getStringExtra(EXTRA_LABEL) ?: "Scanning…",
                intent.getIntExtra(EXTRA_FOUND, 0),
            )
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun startForegroundScan(label: String, found: Int) {
        startForeground(NOTIF_ID, buildNotification(label, found))
    }

    private fun updateNotification(label: String, found: Int) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ID, buildNotification(label, found))
    }

    private fun buildNotification(label: String, found: Int) =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle("WhiteDNS – $label")
            .setContentText("Found: $found endpoints")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE,
                )
            )
            .build()

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "Scan progress",
                NotificationManager.IMPORTANCE_LOW,
            )
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "whitescan_scan"
        const val NOTIF_ID = 1
        const val ACTION_START = "com.whitescan.START"
        const val ACTION_UPDATE = "com.whitescan.UPDATE"
        const val ACTION_STOP = "com.whitescan.STOP"
        const val EXTRA_LABEL = "label"
        const val EXTRA_FOUND = "found"

        fun intentStart(ctx: Context, label: String) =
            Intent(ctx, ScanService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_LABEL, label)
            }

        fun intentUpdate(ctx: Context, label: String, found: Int) =
            Intent(ctx, ScanService::class.java).apply {
                action = ACTION_UPDATE
                putExtra(EXTRA_LABEL, label)
                putExtra(EXTRA_FOUND, found)
            }

        fun intentStop(ctx: Context) =
            Intent(ctx, ScanService::class.java).apply { action = ACTION_STOP }
    }
}
