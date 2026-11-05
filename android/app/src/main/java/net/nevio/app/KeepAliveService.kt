package net.nevio.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Keeps the process alive in proxy mode (without a VPN the system would stop
 * it in the background, and apps would lose the proxy). Its notification is
 * as quiet as Android allows; other apps can only read it if the user gives
 * them notification access.
 */
class KeepAliveService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.keepalive_channel), NotificationManager.IMPORTANCE_MIN)
                .apply { setShowBadge(false) })
        val open = PendingIntent.getActivity(this, 0,
            Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.keepalive_text))
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(ID, n)
        }
        if (intent == null) {
            // Restarted by the system after it stopped the process: bring the proxy back.
            kotlin.concurrent.thread(name = "nevio-restart") { net.nevio.core.mobile.Mobile.connect() }
        }
        return START_STICKY
    }

    companion object {
        const val CHANNEL = "background"
        const val ID = 1
    }
}
