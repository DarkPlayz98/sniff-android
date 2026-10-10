package com.sniff.app

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

/** Quick Settings tile: tap to pause / resume Sniff. If protection isn't set up yet, opens the app. */
class SniffTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        update()
    }

    override fun onClick() {
        super.onClick()
        if (!MainActivity.isServiceEnabled(this)) {
            openApp()
            return
        }
        if (Prefs.isPaused(this)) Prefs.resume(this) else Prefs.pauseForever(this)
        update()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    private fun openApp() {
        val i = Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                val pi = PendingIntent.getActivity(this, 1, i, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(i)
            }
        } catch (_: Throwable) {}
    }

    private fun update() {
        val tile = qsTile ?: return
        val r = Lang.wrap(this)
        val enabled = MainActivity.isServiceEnabled(this)
        val paused = Prefs.isPaused(this)
        tile.icon = Icon.createWithResource(this, R.drawable.ic_stat_sniff)
        tile.label = r.getString(R.string.tile_label)
        tile.state = when {
            !enabled -> Tile.STATE_INACTIVE
            paused -> Tile.STATE_INACTIVE
            else -> Tile.STATE_ACTIVE
        }
        val sub = r.getString(when {
            !enabled -> R.string.tile_off
            paused -> R.string.tile_paused
            else -> R.string.tile_on
        })
        if (Build.VERSION.SDK_INT >= 29) tile.subtitle = sub
        tile.contentDescription = "${r.getString(R.string.tile_label)}: $sub"
        try { tile.updateTile() } catch (_: Throwable) {}
    }
}
