package com.sniff.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView

class MainActivity : Activity() {

    companion object { const val EXTRA_TEXT = "sniff_text" }

    private lateinit var status: TextView
    private lateinit var statusDot: View
    private lateinit var toggle: Button
    private lateinit var input: EditText
    private lateinit var checkBtn: Button
    private lateinit var say: TextView
    private lateinit var sayBody: TextView
    private lateinit var verdict: View
    private lateinit var vAccent: View
    private lateinit var vAnswer: TextView
    private lateinit var vPlain: TextView
    private lateinit var vFlagsH: TextView
    private lateinit var vFlags: TextView
    private lateinit var vTodoH: TextView
    private lateinit var vTodo: TextView
    private lateinit var vSource: TextView
    private var checkSeq = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        statusDot = findViewById(R.id.status_dot)
        toggle = findViewById(R.id.toggle)
        input = findViewById(R.id.input)
        checkBtn = findViewById(R.id.check)
        say = findViewById(R.id.say)
        sayBody = findViewById(R.id.say_body)
        verdict = findViewById(R.id.verdict)
        vAccent = findViewById(R.id.v_accent)
        vAnswer = findViewById(R.id.v_answer)
        vPlain = findViewById(R.id.v_plain)
        vFlagsH = findViewById(R.id.v_flags_h)
        vFlags = findViewById(R.id.v_flags)
        vTodoH = findViewById(R.id.v_todo_h)
        vTodo = findViewById(R.id.v_todo)
        vSource = findViewById(R.id.v_source)

        Alerts.ensureChannel(this)
        SniffApi.warmUp()
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 7)

        toggle.setOnClickListener { if (isServiceEnabled()) openAccessibility() else explainThenOpen() }
        checkBtn.setOnClickListener { runCheck() }
        findViewById<Button>(R.id.paste).setOnClickListener {
            val cm = getSystemService(ClipboardManager::class.java)
            val t = cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
            if (!t.isNullOrBlank()) { input.setText(t); runCheck() }
        }
        val sw = findViewById<Switch>(R.id.auto_close)
        sw.isChecked = Prefs.autoClose(this)
        sw.setOnCheckedChangeListener { _, on -> Prefs.setAutoClose(this, on) }
        findViewById<TextView>(R.id.web).setOnClickListener {
            try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://sniff-orpin.vercel.app"))) } catch (_: Throwable) {}
        }
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
        status.text = getString(if (on) R.string.protection_on else R.string.protection_off)
        statusDot.backgroundTintList = ColorStateList.valueOf(getColor(if (on) R.color.safe else R.color.danger))
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

    /** Web wording: scam / sus / safe */
    private fun showVerdict(kind: String, plain: String, flags: List<String>, todo: List<String>, source: String) {
        val color = getColor(when (kind) { "scam" -> R.color.danger; "sus" -> R.color.warn; else -> R.color.safe })
        vAnswer.text = when (kind) { "scam" -> "Don't click. Don't reply."; "sus" -> "Be careful."; else -> "Safe to open." }
        vAnswer.setTextColor(color)
        vAccent.setBackgroundColor(color)
        vPlain.text = plain
        vFlagsH.visibility = if (flags.isEmpty()) View.GONE else View.VISIBLE
        vFlags.visibility = vFlagsH.visibility
        vFlags.text = flags.take(4).joinToString("\n") { "•  $it" }
        vTodoH.visibility = if (todo.isEmpty()) View.GONE else View.VISIBLE
        vTodo.visibility = vTodoH.visibility
        vTodo.text = todo.take(4).joinToString("\n") { "•  $it" }
        vSource.text = source
        verdict.visibility = View.VISIBLE
    }

    private fun runCheck() {
        val text = input.text?.toString()?.trim().orEmpty()
        if (text.isEmpty()) return
        val seq = ++checkSeq
        checkBtn.isEnabled = false
        checkBtn.text = getString(R.string.checking)
        // instant on-device read first
        val local = ScamRules.check(text)
        val lk = if (local.score >= 60) "scam" else if (local.score >= 30) "sus" else null
        if (lk != null) {
            showVerdict(lk, if (lk == "scam") "This looks like a scam." else "Something here doesn't add up. Check before you act.",
                local.reasons, emptyList(), "Quick check on your phone. Sniff AI is taking a closer look…")
        } else verdict.visibility = View.GONE
        SniffApi.checkAsync(text) { v ->
            runOnUiThread {
                if (seq != checkSeq) return@runOnUiThread
                checkBtn.isEnabled = true
                checkBtn.text = getString(R.string.check_button)
                if (v != null) {
                    val type = v.scamType.trim().removeSuffix(".")
                    val kind = when (v.verdict) { "SCAM" -> "scam"; "SUSPICIOUS" -> "sus"; else -> "safe" }
                    val plain = v.summary.ifBlank {
                        when (kind) {
                            "scam" -> "This looks like a scam" + (if (type.isNotEmpty()) ": $type." else ".")
                            "sus" -> "Something here doesn't add up" + (if (type.isNotEmpty()) " ($type)" else "") + ". Check before you act."
                            else -> "I didn't find anything risky in this."
                        }
                    }
                    showVerdict(kind, plain, v.flags, v.whatToDo, "Checked by Sniff AI. Your message is never stored.")
                } else {
                    val kind = lk ?: "safe"
                    showVerdict(kind,
                        when (kind) {
                            "scam" -> "This looks like a scam."
                            "sus" -> "Something here doesn't add up. Check before you act."
                            else -> "No obvious scam signs. I couldn't reach Sniff AI, so this was a quick check only."
                        },
                        local.reasons, if (kind == "safe") emptyList() else listOf("Don't click any link, reply, or pay anything."),
                        "Quick check on your phone (offline).")
                }
            }
        }
    }
}
