package com.sniff.app

import android.content.Context

object Prefs {
    private const val FILE = "sniff"
    private const val AUTO_CLOSE = "auto_close"
    fun autoClose(ctx: Context): Boolean = ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).getBoolean(AUTO_CLOSE, true)
    fun setAutoClose(ctx: Context, on: Boolean) {
        ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE).edit().putBoolean(AUTO_CLOSE, on).apply()
    }
}
