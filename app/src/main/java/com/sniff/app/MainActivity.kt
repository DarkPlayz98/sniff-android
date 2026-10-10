package com.sniff.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView

class MainActivity : Activity() {

    companion object { const val EXTRA_TEXT = "sniff_text" }

    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var input: EditText
    private lateinit var result: TextView
    private lateinit var checkBtn: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        toggle = findViewById(R.id.toggle)
        input = findViewById(R.id.input)
        result = findViewById(R.id.result)
        checkBtn = findViewById(R.id.check)

        Alerts.ensureChannel(this)
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7)
        }

        toggle.setOnClickListener {
            if (isServiceEnabled()) openAccessibility() else explainThenOpen()
        }
        checkBtn.setOnClickListener { runCheck() }
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(i: Intent?) {
        val t = i?.getStringExtra(EXTRA_TEXT) ?: return
        input.setText(t)
        runCheck()
    }

    override fun onResume() {
        super.onResume()
        val on = isServiceEnabled()
        status.text = getString(if (on) R.string.status_on else R.string.status_off)
        status.setTextColor(getColor(if (on) R.color.safe else R.color.danger))
        toggle.text = getString(if (on) R.string.turn_off else R.string.turn_on)
    }

    private fun isServiceEnabled(): Boolean {
        val me = ComponentName(this, SniffAccessibilityService::class.java)
        val enabled = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(enabled)
        for (s in splitter) {
            val cn = ComponentName.unflattenFromString(s) ?: continue
            if (cn == me) return true
        }
        return false
    }

    private fun explainThenOpen() {
        AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title)
            .setMessage(R.string.dialog_body)
            .setPositiveButton(R.string.dialog_ok) { _, _ -> openAccessibility() }
            .setNegativeButton(R.string.dialog_cancel, null)
            .show()
    }

    private fun openAccessibility() {
        try {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: Throwable) {
            startActivity(Intent(Settings.ACTION_SETTINGS))
        }
    }

    private fun runCheck() {
        val text = input.text?.toString()?.trim().orEmpty()
        if (text.isEmpty()) return
        checkBtn.isEnabled = false
        result.visibility = View.VISIBLE
        result.setTextColor(getColor(R.color.muted))
        result.text = getString(R.string.checking)
        val local = ScamRules.check(text)
        Thread {
            val v = SniffApi.check(text)
            runOnUiThread {
                checkBtn.isEnabled = true
                if (v != null) {
                    val color = when (v.verdict) {
                        "SCAM" -> R.color.danger
                        "SUSPICIOUS" -> R.color.warn
                        else -> R.color.safe
                    }
                    val head = when (v.verdict) {
                        "SCAM" -> "Scam. Don't click or reply."
                        "SUSPICIOUS" -> "Suspicious. Be careful."
                        else -> "Looks safe."
                    }
                    val sb = StringBuilder(head)
                    if (v.summary.isNotBlank()) sb.append("\n\n").append(v.summary)
                    v.flags.take(4).forEach { sb.append("\n• ").append(it) }
                    if (v.whatToDo.isNotEmpty()) {
                        sb.append("\n\nWhat to do:")
                        v.whatToDo.take(4).forEach { sb.append("\n• ").append(it) }
                    }
                    result.setTextColor(getColor(color))
                    result.text = sb.toString()
                } else {
                    // Offline: on-device rules only
                    val risky = local.score >= 60
                    val maybe = local.score >= 30
                    result.setTextColor(getColor(if (risky) R.color.danger else if (maybe) R.color.warn else R.color.safe))
                    val sb = StringBuilder(
                        if (risky) "Likely scam (quick check, offline)." else if (maybe) "Suspicious (quick check, offline)."
                        else "No obvious scam signs (quick check, offline)."
                    )
                    local.reasons.take(4).forEach { sb.append("\n• ").append(it) }
                    result.text = sb.toString()
                }
            }
        }.start()
    }
}
