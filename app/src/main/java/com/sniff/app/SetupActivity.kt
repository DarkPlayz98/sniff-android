package com.sniff.app

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.TextView

/** First-run setup: three big one-tap steps with live checkmarks. Re-opened from home when something is off. */
class SetupActivity : Activity() {

    private val handler = Handler(Looper.getMainLooper())
    private var leaving = false

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(Lang.wrap(newBase)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        Prefs.markSetupSeen(this)
        findViewById<View>(R.id.s_step1).setOnClickListener { if (!Setup.screenOn(this)) openAccessibility(this) }
        findViewById<View>(R.id.s_step2).setOnClickListener { if (!Setup.overlayOn(this)) openOverlay() }
        findViewById<View>(R.id.s_step3).setOnClickListener { if (!Setup.notifOn(this)) askNotifications() }
        findViewById<View>(R.id.s_step3).visibility = if (Build.VERSION.SDK_INT >= 33) View.VISIBLE else View.GONE
        findViewById<Button>(R.id.s_home).setOnClickListener { goHome() }
        findViewById<TextView>(R.id.s_skip).setOnClickListener { goHome() }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun render() {
        val a = Setup.screenOn(this)
        val o = Setup.overlayOn(this)
        val n = Setup.notifOn(this)
        bindStep(R.id.s_mark1, "1", a)
        bindStep(R.id.s_mark2, "2", o)
        bindStep(R.id.s_mark3, "3", n)
        findViewById<View>(R.id.s_hint1).visibility = if (a) View.GONE else View.VISIBLE
        val done = a && o && n
        findViewById<View>(R.id.s_done).visibility = if (done) View.VISIBLE else View.GONE
        findViewById<View>(R.id.s_skip).visibility = if (done) View.GONE else View.VISIBLE
        if (done && !leaving) {
            leaving = true
            handler.postDelayed({ if (!isFinishing && !isDestroyed) goHome() }, 1600)
        }
    }

    private fun bindStep(id: Int, num: String, done: Boolean) {
        val v = findViewById<TextView>(id)
        v.text = if (done) "✓" else num
        v.backgroundTintList = ColorStateList.valueOf(getColor(if (done) R.color.safe else R.color.ink))
        v.contentDescription = getString(if (done) R.string.step_done else R.string.step_todo)
    }

    private fun openOverlay() {
        val tries = listOf(
            Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, Uri.parse("package:$packageName")),
            Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION),
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
        )
        for (t in tries) { try { startActivity(t); return } catch (_: Throwable) {} }
    }

    private fun askNotifications() {
        if (Build.VERSION.SDK_INT < 33) return
        try { requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 8) } catch (_: Throwable) { openNotifSettings() }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != 8 || Build.VERSION.SDK_INT < 33) return
        val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        // denied for good (or the dialog can't show any more): send the user to the switch instead
        if (!granted && !shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) openNotifSettings()
        render()
    }

    private fun openNotifSettings() {
        val tries = listOf(
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, packageName),
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
        )
        for (t in tries) { try { startActivity(t); return } catch (_: Throwable) {} }
    }

    private fun goHome() {
        handler.removeCallbacksAndMessages(null)
        try {
            startActivity(Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
        } catch (_: Throwable) {}
        finish()
    }

    companion object {
        /** Deep link straight to Sniff's switch where the phone supports it, else the Accessibility list. */
        fun openAccessibility(a: Activity) {
            val cn = android.content.ComponentName(a, SniffAccessibilityService::class.java).flattenToString()
            val tries = ArrayList<Intent>()
            if (Build.VERSION.SDK_INT >= 33) tries.add(Intent("android.settings.ACCESSIBILITY_DETAILS_SETTINGS")
                .putExtra(Intent.EXTRA_COMPONENT_NAME, cn))
            tries.add(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            tries.add(Intent(Settings.ACTION_SETTINGS))
            for (t in tries) { try { a.startActivity(t); return } catch (_: Throwable) {} }
        }
    }
}
