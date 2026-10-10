package com.sniff.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/** Minimal notification, used only as a fallback when the on-screen banner can't be shown. */
object Alerts {
    const val CHANNEL_ID = "sniff_warnings"
    private const val OLD_CHANNEL = "scam_alerts"
    private var nextId = 1000

    fun ensureChannel(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return
        try { nm.deleteNotificationChannel(OLD_CHANNEL) } catch (_: Throwable) {}
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            val ch = NotificationChannel(CHANNEL_ID, ctx.getString(R.string.channel_name), NotificationManager.IMPORTANCE_DEFAULT)
            ch.description = ctx.getString(R.string.channel_desc)
            ch.enableVibration(false)
            ch.setShowBadge(false)
            nm.createNotificationChannel(ch)
        }
    }

    fun canNotify(ctx: Context): Boolean =
        Build.VERSION.SDK_INT < 33 ||
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    fun warn(ctx: Context, title: String, reason: String, snippet: String, scam: Boolean) {
        if (!canNotify(ctx)) return
        ensureChannel(ctx)
        val open = Intent(ctx, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            putExtra(MainActivity.EXTRA_TEXT, snippet)
        }
        val pi = PendingIntent.getActivity(ctx, nextId, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = Notification.Builder(ctx, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_sniff)
            .setContentTitle(title)
            .setContentText(reason)
            .setColor(if (scam) 0xFFC8372F.toInt() else 0xFFB7741A.toInt())
            .setAutoCancel(true)
            .setTimeoutAfter(10 * 60 * 1000L)
            .setContentIntent(pi)
            .build()
        try { ctx.getSystemService(NotificationManager::class.java)?.notify(nextId++, n) } catch (_: SecurityException) {}
    }
}
