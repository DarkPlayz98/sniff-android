package com.sniff.app

import android.accessibilityservice.AccessibilityService
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.Locale

/**
 * Reads visible text on screen, runs fast on-device rules, and asks the live Sniff checker
 * only when something looks risky or a new link appears. Nothing is written to disk.
 */
class SniffAccessibilityService : AccessibilityService() {

    companion object {
        @Volatile var running = false
        private const val DEBOUNCE_MS = 700L
        private const val DEDUPE_MS = 10 * 60 * 1000L
        private const val API_GAP_MS = 8000L
        private const val LOCAL_API_THRESHOLD = 40
        private const val LOCAL_WARN_THRESHOLD = 60
        private const val MAX_NODES = 800
        private const val MAX_DEPTH = 40

        /** Banking / UPI / password-manager apps: never read. */
        val SKIP_PACKAGES = setOf(
            "com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus", "com.sbi.upi", "com.sbi.yonobusiness",
            "com.snapwork.hdfc", "com.hdfcbank.payzapp", "com.csam.icici.bank.imobile", "com.icicibank.pockets",
            "com.axis.mobile", "com.msf.kbank.mobile", "com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge",
            "com.phonepe.app", "net.one97.paytm", "com.google.android.apps.nbu.paisa.user", "in.org.npci.upiapp",
            "in.amazon.mShop.android.shopping.pay", "com.dreamplug.androidapp", "com.mobikwik_new", "com.freecharge.android",
            "com.bankofbaroda.mconnect", "com.infrasofttech.indianbank", "com.pnb.pnbone", "com.canarabank.mobility",
            "com.unionbankofindia.vyom", "com.idfcfirstbank.optimus", "com.yesbank.yesmobile", "com.fss.idbi",
            "com.x8bit.bitwarden", "com.agilebits.onepassword", "com.lastpass.lpandroid", "com.google.android.gms",
            "com.android.settings", "com.google.android.inputmethod.latin", "com.samsung.android.honeyboard"
        )
    }

    private val main = Handler(Looper.getMainLooper())
    private lateinit var worker: Handler
    private lateinit var workerThread: HandlerThread
    private lateinit var banner: OverlayBanner

    private val seen = HashMap<String, Long>()          // in-memory only
    private var lastApiAt = 0L
    private var pending: Candidate? = null
    private var currentPackage: String? = null

    private data class Candidate(val text: String, val local: ScamRules.Result, val keys: List<String>)

    private val scan = Runnable { scanNow() }
    private val drainPending = Runnable { worker.post { drain() } }

    override fun onServiceConnected() {
        super.onServiceConnected()
        running = true
        workerThread = HandlerThread("sniff-worker").also { it.start() }
        worker = Handler(workerThread.looper)
        banner = OverlayBanner(this)
        Alerts.ensureChannel(this)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val pkg = event?.packageName?.toString() ?: return
        if (pkg == packageName || pkg in SKIP_PACKAGES) return
        currentPackage = pkg
        main.removeCallbacks(scan)
        main.postDelayed(scan, DEBOUNCE_MS)
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        running = false
        main.removeCallbacksAndMessages(null)
        if (::banner.isInitialized) banner.dismiss()
        if (::workerThread.isInitialized) workerThread.quitSafely()
        super.onDestroy()
    }

    private fun scanNow() {
        val root = try { rootInActiveWindow } catch (_: Throwable) { null } ?: return
        val pkg = root.packageName?.toString()
        if (pkg == null || pkg == packageName || pkg in SKIP_PACKAGES) return
        val texts = ArrayList<String>()
        collect(root, texts, 0, intArrayOf(0))
        if (texts.isEmpty()) return
        worker.post { evaluate(texts) }
    }

    private fun collect(node: AccessibilityNodeInfo?, out: MutableList<String>, depth: Int, count: IntArray) {
        if (node == null || depth > MAX_DEPTH || count[0] > MAX_NODES) return
        count[0]++
        if (node.isPassword) return          // never read password fields (or their children)
        if (node.isVisibleToUser) {
            val t = node.text?.toString()?.trim()
            if (!t.isNullOrEmpty() && t.length >= 6) out.add(t.take(2000))
            else {
                val d = node.contentDescription?.toString()?.trim()
                if (!d.isNullOrEmpty() && d.length >= 12) out.add(d.take(1000))
            }
        }
        for (i in 0 until node.childCount) {
            val c = try { node.getChild(i) } catch (_: Throwable) { null } ?: continue
            collect(c, out, depth + 1, count)
            if (Build.VERSION.SDK_INT < 33) {
                @Suppress("DEPRECATION")
                try { c.recycle() } catch (_: Throwable) {}
            }
        }
    }

    private fun norm(s: String) = s.lowercase(Locale.ROOT).replace(Regex("\\s+"), " ").trim()

    private fun isFresh(key: String, now: Long): Boolean {
        val t = seen[key]
        return t == null || now - t > DEDUPE_MS
    }

    /** Runs on the worker thread. */
    private fun evaluate(texts: List<String>) {
        val now = SystemClock.elapsedRealtime()
        if (seen.size > 2000) seen.entries.removeAll { now - it.value > DEDUPE_MS }

        var best: Candidate? = null
        for (raw in texts.distinct()) {
            val local = ScamRules.check(raw)
            val newUrls = local.urls.map { "u:" + ScamRules.hostOf(it) + "|" + it.lowercase(Locale.ROOT).take(200) }
                .filter { isFresh(it, now) }
            val textKey = "t:" + norm(raw).hashCode()
            val textFresh = isFresh(textKey, now)
            val interesting = (local.score >= LOCAL_API_THRESHOLD && textFresh) || newUrls.isNotEmpty()
            if (!interesting) continue
            val keys = newUrls + textKey
            val cand = Candidate(raw, local, keys)
            if (best == null || cand.local.score > best.local.score ||
                (cand.local.score == best.local.score && cand.local.urls.size > best.local.urls.size)
            ) best = cand
        }
        val b = best ?: return
        // mark everything we decided to look at so it isn't re-checked for 10 minutes
        b.keys.forEach { seen[it] = now }
        val p = pending
        if (p == null || b.local.score >= p.local.score) pending = b
        drain()
    }

    /** Runs on the worker thread. Max one API call every 8 seconds. */
    private fun drain() {
        val c = pending ?: return
        val now = SystemClock.elapsedRealtime()
        val wait = lastApiAt + API_GAP_MS - now
        if (wait > 0) {
            main.removeCallbacks(drainPending)
            main.postDelayed(drainPending, wait)
            return
        }
        pending = null
        lastApiAt = now
        val v = SniffApi.check(c.text.take(1500))
        val hasLink = c.local.urls.isNotEmpty()
        when {
            v != null && v.risky -> alert(v.verdict == "SCAM", hasLink, v.reason, c.text)
            v == null && c.local.score >= LOCAL_WARN_THRESHOLD -> alert(true, hasLink, c.local.topReason, c.text)
            else -> { /* safe: stay quiet */ }
        }
    }

    private fun alert(scam: Boolean, hasLink: Boolean, reason: String, text: String) {
        val title = when {
            hasLink -> "Don't click this link"
            scam -> "This looks like a scam"
            else -> "Be careful with this message"
        }
        val r = reason.ifBlank { "Sniff thinks this may be a scam." }
        Alerts.warn(this, title, r, text.take(1500))
        banner.show("Sniff: $title", r, scam)
    }
}
