package com.sniff.app

import android.content.Context
import android.provider.Settings

/** The three things Sniff needs. Checked live (onResume) by the setup screen and the home status pill. */
object Setup {
    fun screenOn(ctx: Context) = MainActivity.isServiceEnabled(ctx)
    fun overlayOn(ctx: Context) = try { Settings.canDrawOverlays(ctx) } catch (_: Throwable) { false }
    fun notifOn(ctx: Context) = Alerts.canNotify(ctx)
    fun allDone(ctx: Context) = screenOn(ctx) && overlayOn(ctx) && notifOn(ctx)
}
