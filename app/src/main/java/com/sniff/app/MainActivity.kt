package com.sniff.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.TextUtils
import android.text.format.DateFormat
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.NumberFormat
import java.util.Date

class MainActivity : Activity() {

    companion object {
        const val EXTRA_TEXT = "sniff_text"
        const val EXTRA_HOST = "sniff_host"
        const val EXTRA_SENDER = "sniff_sender"

        fun isServiceEnabled(ctx: Context): Boolean {
            val me = ComponentName(ctx, SniffAccessibilityService::class.java)
            val enabled = try {
                Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            } catch (_: Throwable) { null } ?: return false
            val splitter = TextUtils.SimpleStringSplitter(':')
            splitter.setString(enabled)
            for (s in splitter) {
                val cn = ComponentName.unflattenFromString(s) ?: continue
                if (cn == me) return true
            }
            return false
        }
    }

    private lateinit var status: TextView
    private lateinit var statusDot: View
    private lateinit var toggle: Button
    private lateinit var input: EditText
    private lateinit var checkBtn: Button
    private lateinit var verdict: View
    private lateinit var vAccent: View
    private lateinit var vAnswer: TextView
    private lateinit var vPlain: TextView
    private lateinit var vFlagsH: TextView
    private lateinit var vFlags: TextView
    private lateinit var vTodoH: TextView
    private lateinit var vTodo: TextView
    private lateinit var vSource: TextView
    private lateinit var vTrust: Button
    private lateinit var vHelp: View
    private lateinit var stats: TextView
    private lateinit var pauseRow: View
    private lateinit var resumeBtn: Button
    private lateinit var statusPill: Button
    private lateinit var finishSetup: Button
    private var appBanner: OverlayBanner? = null
    private var checkSeq = 0
    private val pauseTick = Runnable { if (!isFinishing && !isDestroyed) refreshStatus() }

    // what the current verdict is about (for "This is safe" and "warn family")
    private var curText = ""
    private var curHost: String? = null
    private var curSender: String? = null
    private var curPlain = ""

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(Lang.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        status = findViewById(R.id.status)
        statusDot = findViewById(R.id.status_dot)
        toggle = findViewById(R.id.toggle)
        input = findViewById(R.id.input)
        checkBtn = findViewById(R.id.check)
        verdict = findViewById(R.id.verdict)
        vAccent = findViewById(R.id.v_accent)
        vAnswer = findViewById(R.id.v_answer)
        vPlain = findViewById(R.id.v_plain)
        vFlagsH = findViewById(R.id.v_flags_h)
        vFlags = findViewById(R.id.v_flags)
        vTodoH = findViewById(R.id.v_todo_h)
        vTodo = findViewById(R.id.v_todo)
        vSource = findViewById(R.id.v_source)
        vTrust = findViewById(R.id.v_trust)
        vHelp = findViewById(R.id.v_help)
        stats = findViewById(R.id.stats)
        pauseRow = findViewById(R.id.pause_row)
        resumeBtn = findViewById(R.id.resume)
        statusPill = findViewById(R.id.status_pill)
        finishSetup = findViewById(R.id.finish_setup)
        statusPill.setOnClickListener { onPillTap() }
        finishSetup.setOnClickListener { startActivity(Intent(this, SetupActivity::class.java)) }
        findViewById<Button>(R.id.test_sniff).setOnClickListener { testSniff() }

        Alerts.ensureChannel(this)
        SniffApi.warmUp()

        toggle.setOnClickListener { if (isServiceEnabled(this)) openAccessibility() else explainThenOpen() }
        checkBtn.setOnClickListener { runCheck() }
        findViewById<Button>(R.id.paste).setOnClickListener { checkClipboard() }
        val sw = findViewById<Switch>(R.id.auto_close)
        sw.isChecked = Prefs.autoClose(this)
        sw.setOnCheckedChangeListener { _, on -> Prefs.setAutoClose(this, on) }
        findViewById<TextView>(R.id.web).setOnClickListener { openUrl("https://sniff-orpin.vercel.app") }

        findViewById<Button>(R.id.pause_1h).setOnClickListener { Prefs.pauseFor(this, 60 * 60 * 1000L); refreshStatus() }
        findViewById<Button>(R.id.pause_forever).setOnClickListener { Prefs.pauseForever(this); refreshStatus() }
        resumeBtn.setOnClickListener { Prefs.resume(this); refreshStatus() }

        findViewById<Button>(R.id.open_history).setOnClickListener { startActivity(Intent(this, HistoryActivity::class.java)) }
        findViewById<Button>(R.id.open_trusted).setOnClickListener { startActivity(Intent(this, TrustedActivity::class.java)) }

        val langButtons = listOf(R.id.lang_en, R.id.lang_hi, R.id.lang_te).map { findViewById<Button>(it) }
        val cur = Prefs.lang(this)
        langButtons.forEachIndexed { i, b ->
            val selected = Lang.CODES[i] == cur
            b.setBackgroundResource(if (selected) R.drawable.bg_pill_dark else R.drawable.bg_pill_glass)
            b.setTextColor(getColor(if (selected) R.color.on_pill else R.color.ink))
            b.setOnClickListener {
                if (Lang.CODES[i] != Prefs.lang(this)) {
                    Prefs.setLang(this, Lang.CODES[i])
                    try {
                        android.service.quicksettings.TileService.requestListeningState(
                            this, ComponentName(this, SniffTileService::class.java))
                    } catch (_: Throwable) {}
                    recreate()
                }
            }
        }

        vTrust.setOnClickListener { trustCurrent() }
        findViewById<Button>(R.id.v_call).setOnClickListener { dial1930(this) }
        findViewById<Button>(R.id.v_report).setOnClickListener { openUrl("https://cybercrime.gov.in") }
        findViewById<Button>(R.id.v_family).setOnClickListener { warnFamily() }

        // a fresh launch (not a rotation / language change) acts on what it was opened with
        if (savedInstanceState == null) {
            val hasText = intent?.action == Intent.ACTION_SEND || intent?.action == Intent.ACTION_PROCESS_TEXT ||
                intent?.hasExtra(EXTRA_TEXT) == true
            handleIntent(intent)
            // first launch: walk through the 3 setup steps once (home re-offers them if anything is off)
            if (!hasText && !Prefs.setupSeen(this) && !Setup.allDone(this)) {
                startActivity(Intent(this, SetupActivity::class.java))
            }
        }
    }

    override fun onDestroy() {
        appBanner?.release()
        appBanner = null
        super.onDestroy()
    }

    /** The status pill fixes whatever is missing in one tap. */
    private fun onPillTap() {
        when {
            !isServiceEnabled(this) -> SetupActivity.openAccessibility(this)
            Prefs.isPaused(this) -> { Prefs.resume(this); refreshStatus() }
            !Setup.allDone(this) -> startActivity(Intent(this, SetupActivity::class.java))
            else -> Toast.makeText(this, R.string.status_all_good, Toast.LENGTH_SHORT).show()
        }
    }

    /** Shows a sample scam warning so the user knows what a real alert looks like. */
    private fun testSniff() {
        val sample = getString(R.string.test_sample)
        val svc = SniffAccessibilityService.instance
        if (svc != null) { svc.showTestBanner(sample); return }
        if (Setup.overlayOn(this)) {
            val b = appBanner ?: OverlayBanner(applicationContext, WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY)
                .also { appBanner = it }
            b.show("sniff-test", getString(R.string.banner_link), getString(R.string.test_reason), true,
                onTap = { if (!isFinishing && !isDestroyed) { input.setText(sample); runCheck() } },
                onFail = { Toast.makeText(this, R.string.test_needs_setup, Toast.LENGTH_LONG).show() })
            return
        }
        Toast.makeText(this, R.string.test_needs_setup, Toast.LENGTH_LONG).show()
        startActivity(Intent(this, SetupActivity::class.java))
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    /** Opened from a warning, from History, from "Share → Sniff", or from "Sniff" in the text-selection menu. */
    private fun handleIntent(i: Intent?) {
        if (i == null) return
        var text: String? = i.getStringExtra(EXTRA_TEXT)
        var host: String? = i.getStringExtra(EXTRA_HOST)
        var sender: String? = i.getStringExtra(EXTRA_SENDER)
        when (i.action) {
            Intent.ACTION_SEND -> {
                val body = i.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                val subject = i.getStringExtra(Intent.EXTRA_SUBJECT)
                text = listOfNotNull(subject?.takeIf { it.isNotBlank() && body?.contains(it) != true }, body)
                    .joinToString("\n").ifBlank { null }
                host = null; sender = null
            }
            Intent.ACTION_PROCESS_TEXT -> {
                text = i.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
                host = null; sender = null
            }
        }
        if (text.isNullOrBlank()) return
        input.setText(text.take(4000))
        runCheck(host, sender)
        // don't re-run this check if the activity is recreated
        setIntent(Intent(this, MainActivity::class.java))
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun refreshStatus() {
        val on = isServiceEnabled(this)
        val until = Prefs.pausedUntil(this)
        val paused = on && until > System.currentTimeMillis()
        status.text = when {
            !on -> getString(R.string.protection_off)
            paused && until == Long.MAX_VALUE -> getString(R.string.protection_paused)
            paused -> getString(R.string.protection_paused_until, DateFormat.getTimeFormat(this).format(Date(until)))
            else -> getString(R.string.protection_on)
        }
        statusDot.backgroundTintList = ColorStateList.valueOf(getColor(when {
            !on -> R.color.danger
            paused -> R.color.warn
            else -> R.color.safe
        }))
        toggle.text = getString(if (on) R.string.turn_off else R.string.turn_on)
        pauseRow.visibility = if (on && !paused) View.VISIBLE else View.GONE
        resumeBtn.visibility = if (paused) View.VISIBLE else View.GONE
        statusPill.text = when {
            !on -> getString(R.string.status_off)
            paused && until == Long.MAX_VALUE -> getString(R.string.status_paused)
            paused -> getString(R.string.status_paused_until, DateFormat.getTimeFormat(this).format(Date(until)))
            else -> getString(R.string.status_on)
        }
        statusPill.backgroundTintList = statusDot.backgroundTintList
        statusPill.contentDescription = statusPill.text
        finishSetup.visibility = if (Setup.allDone(this)) View.GONE else View.VISIBLE
        // a timed pause ends on its own: refresh the pill when it does
        statusPill.removeCallbacks(pauseTick)
        if (paused && until != Long.MAX_VALUE) statusPill.postDelayed(pauseTick, (until - System.currentTimeMillis()).coerceIn(1000L, 60 * 60 * 1000L) + 500)
        val nf = NumberFormat.getIntegerInstance()
        stats.text = getString(R.string.stats, nf.format(Prefs.checked(this)), nf.format(Prefs.blocked(this)))
    }

    private fun checkClipboard() {
        val cm = getSystemService(ClipboardManager::class.java)
        val t = try {
            cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
        } catch (_: Throwable) { null }
        if (t.isNullOrBlank()) {
            Toast.makeText(this, R.string.clipboard_empty, Toast.LENGTH_SHORT).show()
            return
        }
        input.setText(t.take(4000))
        runCheck()
    }

    private fun explainThenOpen() {
        AlertDialog.Builder(this)
            .setTitle(R.string.dialog_title)
            .setMessage(R.string.dialog_body)
            .setPositiveButton(R.string.dialog_ok) { _, _ -> openAccessibility() }
            .setNegativeButton(R.string.dialog_cancel, null)
            .show()
    }

    private fun openAccessibility() = SetupActivity.openAccessibility(this)

    private fun openUrl(url: String) {
        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (_: Throwable) {}
    }

    // ---------- verdict ----------

    /** Web wording: scam / sus / safe */
    private fun showVerdict(kind: String, plain: String, flags: List<String>, todo: List<String>, source: String) {
        val color = getColor(when (kind) { "scam" -> R.color.danger; "sus" -> R.color.warn; else -> R.color.safe })
        vAnswer.text = getString(when (kind) { "scam" -> R.string.verdict_scam; "sus" -> R.string.verdict_sus; else -> R.string.verdict_safe })
        vAnswer.setTextColor(color)
        vAccent.setBackgroundColor(color)
        vPlain.text = plain
        curPlain = plain
        val f = flags.filter { it.isNotBlank() }.take(4)
        val t = todo.filter { it.isNotBlank() }.take(4)
        vFlagsH.visibility = if (f.isEmpty()) View.GONE else View.VISIBLE
        vFlags.visibility = vFlagsH.visibility
        vFlags.text = f.joinToString("\n") { "•  $it" }
        vTodoH.visibility = if (t.isEmpty()) View.GONE else View.VISIBLE
        vTodo.visibility = vTodoH.visibility
        vTodo.text = t.joinToString("\n") { "•  $it" }
        vSource.text = source
        val risky = kind == "scam" || kind == "sus"
        vHelp.visibility = if (risky) View.VISIBLE else View.GONE
        bindTrust(risky)
        verdict.visibility = View.VISIBLE
    }

    private fun bindTrust(risky: Boolean) {
        val set = Prefs.trusted(this)
        val host = curHost
        val sender = curSender
        when {
            !risky -> vTrust.visibility = View.GONE
            host != null && !Prefs.isTrustedHost(set, host) -> {
                vTrust.text = getString(R.string.trust_site, host)
                vTrust.visibility = View.VISIBLE
            }
            host == null && sender != null && !Prefs.isTrustedSender(set, sender) -> {
                vTrust.text = getString(R.string.trust_sender, sender)
                vTrust.visibility = View.VISIBLE
            }
            else -> vTrust.visibility = View.GONE
        }
    }

    private fun trustCurrent() {
        val host = curHost
        val sender = curSender
        val label = when {
            host != null -> { Prefs.addTrusted(this, Prefs.SITE + host.lowercase().removePrefix("www.")); host }
            sender != null -> { Prefs.addTrusted(this, Prefs.SENDER + Prefs.normSender(sender)); sender }
            else -> return
        }
        Toast.makeText(this, getString(R.string.trusted_done, label), Toast.LENGTH_LONG).show()
        vTrust.visibility = View.GONE
        vSource.text = getString(R.string.source_trusted)
    }

    private fun warnFamily() {
        val snippet = curText.replace(Regex("\\s+"), " ").trim().let { if (it.length > 160) it.take(157) + "…" else it }
        val msg = getString(R.string.warn_family_text, snippet, curPlain)
        try {
            getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("Sniff warning", msg))
        } catch (_: Throwable) {}
        Toast.makeText(this, R.string.copied, Toast.LENGTH_SHORT).show()
        val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, msg)
        try { startActivity(Intent.createChooser(send, getString(R.string.warn_family))) } catch (_: Throwable) {}
    }

    private fun runCheck(hostHint: String? = null, senderHint: String? = null) {
        val text = input.text?.toString()?.trim().orEmpty()
        if (text.isEmpty()) return
        val seq = ++checkSeq
        checkBtn.isEnabled = false
        checkBtn.text = getString(R.string.checking)
        // instant on-device read first
        val local = ScamRules.check(text)
        curText = text
        curHost = hostHint ?: local.badHost ?: local.urls.firstOrNull()?.let { ScamRules.hostOf(it) }?.takeIf { it.contains('.') }
        curSender = senderHint ?: if (text.startsWith("From ") && text.contains(":\n"))
            text.substring(5, text.indexOf(":\n")).trim().ifEmpty { null } else null
        Prefs.addChecked(this, 1)
        val lk = if (local.score >= 60) "scam" else if (local.score >= 30) "sus" else null
        if (lk != null) {
            showVerdict(lk, getString(if (lk == "scam") R.string.plain_scam else R.string.plain_sus),
                local.reasons, emptyList(), getString(R.string.source_quick))
        } else verdict.visibility = View.GONE
        SniffApi.checkAsync(text) { v ->
            runOnUiThread {
                if (isFinishing || isDestroyed || seq != checkSeq) return@runOnUiThread
                checkBtn.isEnabled = true
                checkBtn.text = getString(R.string.check_button)
                if (v != null) {
                    val type = v.scamType.trim().removeSuffix(".")
                    val kind = when (v.verdict) { "SCAM" -> "scam"; "SUSPICIOUS" -> "sus"; else -> "safe" }
                    val plain = v.summary.ifBlank {
                        when (kind) {
                            "scam" -> getString(R.string.plain_scam) + (if (type.isNotEmpty()) " ($type)" else "")
                            "sus" -> getString(R.string.plain_sus) + (if (type.isNotEmpty()) " ($type)" else "")
                            else -> getString(R.string.plain_safe)
                        }
                    }
                    showVerdict(kind, plain, v.flags, v.whatToDo, getString(R.string.source_ai))
                } else {
                    val kind = lk ?: "safe"
                    showVerdict(kind,
                        getString(when (kind) {
                            "scam" -> R.string.plain_scam
                            "sus" -> R.string.plain_sus
                            else -> R.string.plain_safe_offline
                        }),
                        local.reasons, if (kind == "safe") emptyList() else listOf(getString(R.string.todo_offline)),
                        getString(R.string.source_offline))
                }
                refreshStatus()
            }
        }
    }
}

/** Opens the dialer with 1930 filled in (never calls by itself). */
fun dial1930(a: Activity) {
    try {
        a.startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930")))
    } catch (_: Throwable) {
        Toast.makeText(a, R.string.no_dialer, Toast.LENGTH_LONG).show()
    }
}
