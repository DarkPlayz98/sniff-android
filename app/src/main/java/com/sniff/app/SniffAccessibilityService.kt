package com.sniff.app

import android.accessibilityservice.AccessibilityService
import android.app.Notification
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.Parcelable
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import java.util.Locale

/**
 * Reads visible text and new notifications, splits them into message-sized chunks, runs the
 * on-device rules instantly and sends every NEW message/link to Sniff AI (deduped by content hash,
 * max 3 in flight, small priority queue). Confident local hits warn instantly; the AI verdict then
 * refines or replaces the warning. In browsers, a scam URL is closed and a safe page is opened.
 * Nothing is written to disk.
 */
class SniffAccessibilityService : AccessibilityService() {

    companion object {
        @Volatile var running = false
        private const val DEBOUNCE_MS = 260L          // quiet time after the last screen change
        private const val MAX_WAIT_MS = 800L           // ...but never wait longer than this while the screen keeps changing
        private const val SEEN_TTL_MS = 30 * 60 * 1000L
        private const val SEEN_MAX = 3000
        private const val SOURCE_GAP_MS = 1500L        // min spacing between AI calls for the same source (link host / text)
        private const val QUEUE_MAX = 12
        private const val PER_SCAN_MAX = 6             // new chunks sent to AI from one screen update
        private const val BUDGET_PER_MIN = 40          // protects the shared API key from runaway screens
        private const val LOCAL_WARN = 60              // instant warning (and auto-close in browsers) from local rules
        private const val LOCAL_CAREFUL = 40
        private const val MAX_NODES = 900
        private const val MAX_DEPTH = 45

        /** Banking / UPI / password-manager / system apps: never read. */
        val SKIP_PACKAGES = setOf(
            "com.sbi.lotusintouch", "com.sbi.SBIFreedomPlus", "com.sbi.upi", "com.sbi.yonobusiness",
            "com.snapwork.hdfc", "com.hdfcbank.payzapp", "com.csam.icici.bank.imobile", "com.icicibank.pockets",
            "com.axis.mobile", "com.msf.kbank.mobile", "com.kotak811mobilebankingapp.instantsavingsupiscanandpayrecharge",
            "com.phonepe.app", "net.one97.paytm", "com.google.android.apps.nbu.paisa.user", "in.org.npci.upiapp",
            "in.amazon.mShop.android.shopping.pay", "com.dreamplug.androidapp", "com.mobikwik_new", "com.freecharge.android",
            "com.bankofbaroda.mconnect", "com.infrasofttech.indianbank", "com.pnb.pnbone", "com.canarabank.mobility",
            "com.unionbankofindia.vyom", "com.idfcfirstbank.optimus", "com.yesbank.yesmobile", "com.fss.idbi",
            "com.x8bit.bitwarden", "com.agilebits.onepassword", "com.lastpass.lpandroid", "com.google.android.gms",
            "com.android.settings", "com.google.android.inputmethod.latin", "com.samsung.android.honeyboard",
            "com.android.systemui", "com.google.android.apps.nexuslauncher", "com.sec.android.app.launcher",
            "com.miui.home", "com.android.launcher3", "com.oppo.launcher", "com.vivo.launcher"
        )

        val BROWSERS = setOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary",
            "com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta", "com.microsoft.emmx",
            "org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus",
            "com.brave.browser", "com.opera.browser", "com.opera.mini.native", "com.opera.gx",
            "com.duckduckgo.mobile.android", "com.mi.globalbrowser", "com.android.browser", "com.UCMobile.intl",
            "com.uc.browser.en", "com.vivaldi.browser", "com.kiwibrowser.browser", "com.heytap.browser",
            "com.yandex.browser", "com.cloudmosa.puffinFree"
        )
        private val URL_BAR_IDS = listOf(
            "url_bar", "location_bar_edit_text", "mozac_browser_toolbar_url_view", "url_field", "omnibarTextInput",
            "address_bar", "addressbar", "url_text", "search_box_text", "location_bar", "omnibar", "url"
        )

        fun isBrowser(pkg: String) = pkg in BROWSERS || pkg.contains("browser", ignoreCase = true)
    }

    private class Job(
        val key: String, val text: String, val local: ScamRules.Result, val pkg: String,
        val priority: Int, val source: String, val browserHost: String? = null
    )

    private val main = Handler(Looper.getMainLooper())
    private lateinit var workerThread: HandlerThread
    private lateinit var worker: Handler
    private lateinit var banner: OverlayBanner

    // worker-thread state only
    private val seen = object : LinkedHashMap<String, Long>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > SEEN_MAX
    }
    private val queue = ArrayList<Job>()
    private var active = 0
    private val lastBySource = HashMap<String, Long>()
    private val sentTimes = ArrayDeque<Long>()
    private val lastBrowserHost = HashMap<String, Pair<String, Long>>()
    private val closedAt = HashMap<String, Long>()
    @Volatile private var firstPendingAt = 0L

    private val scan = Runnable { firstPendingAt = 0L; scanNow() }
    private val pumpLater = Runnable { pump() }

    override fun onServiceConnected() {
        super.onServiceConnected()
        running = true
        workerThread = HandlerThread("sniff-scan").also { it.start() }
        worker = Handler(workerThread.looper)
        banner = OverlayBanner(this)
        Alerts.ensureChannel(this)
        SniffApi.warmUp()
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || !::worker.isInitialized) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName || pkg in SKIP_PACKAGES) return
        if (event.eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED) {
            val chunks = notificationChunks(event)
            if (chunks.isNotEmpty()) worker.post { process(pkg, chunks, inBrowser = false) }
            return
        }
        // debounce with a ceiling, so a constantly-changing screen still gets scanned
        val now = SystemClock.uptimeMillis()
        if (firstPendingAt == 0L) firstPendingAt = now
        if (now - firstPendingAt < MAX_WAIT_MS) {
            worker.removeCallbacks(scan)
            worker.postDelayed(scan, DEBOUNCE_MS)
        }
    }

    override fun onInterrupt() {}

    override fun onDestroy() {
        running = false
        main.removeCallbacksAndMessages(null)
        if (::banner.isInitialized) banner.dismiss()
        if (::workerThread.isInitialized) workerThread.quitSafely()
        super.onDestroy()
    }

    // ---------- notifications (incoming SMS / WhatsApp / mail) ----------

    private fun notificationChunks(event: AccessibilityEvent): List<String> {
        val out = ArrayList<String>()
        val n = event.parcelableData as? Notification
        if (n != null) {
            if (n.flags and (Notification.FLAG_ONGOING_EVENT or Notification.FLAG_FOREGROUND_SERVICE) != 0) return out
            if (n.category in setOf(Notification.CATEGORY_PROGRESS, Notification.CATEGORY_TRANSPORT,
                    Notification.CATEGORY_SERVICE, Notification.CATEGORY_SYSTEM, Notification.CATEGORY_CALL)) return out
            val ex: Bundle = n.extras ?: Bundle()
            val title = ex.getCharSequence(Notification.EXTRA_TITLE)?.toString()?.trim().orEmpty()
            val msgs = try {
                @Suppress("DEPRECATION")
                ex.getParcelableArray(Notification.EXTRA_MESSAGES)
            } catch (_: Throwable) { null }
            if (msgs != null && msgs.isNotEmpty()) {
                for (p: Parcelable? in msgs.takeLast(4)) {
                    val b = p as? Bundle ?: continue
                    val t = b.getCharSequence("text")?.toString()?.trim().orEmpty()
                    val s = b.getCharSequence("sender")?.toString()?.trim() ?: title
                    if (t.isNotEmpty()) out.add(if (s.isNotEmpty()) "From $s:\n$t" else t)
                }
            }
            if (out.isEmpty()) {
                val big = ex.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.trim()
                val txt = big ?: ex.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim()
                if (!txt.isNullOrEmpty()) out.add(if (title.isNotEmpty()) "From $title:\n$txt" else txt)
                ex.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.takeLast(4)?.forEach { l ->
                    val s = l?.toString()?.trim()
                    if (!s.isNullOrEmpty()) out.add(s)
                }
            }
        }
        if (out.isEmpty()) {
            val t = event.text?.joinToString("\n") { it?.toString().orEmpty() }?.trim()
            if (!t.isNullOrEmpty()) out.add(t)
        }
        return out
    }

    // ---------- screen scan (worker thread) ----------

    private fun scanNow() {
        val root = try { rootInActiveWindow } catch (_: Throwable) { null } ?: return
        val pkg = root.packageName?.toString() ?: return
        if (pkg == packageName || pkg in SKIP_PACKAGES) return
        val inBrowser = isBrowser(pkg)
        val texts = ArrayList<String>()
        val urlBar = arrayOfNulls<String>(1)
        collect(root, texts, urlBar, inBrowser, 0, intArrayOf(0))
        if (inBrowser) urlBar[0]?.let { checkBrowserUrl(pkg, it) }
        if (texts.isNotEmpty()) process(pkg, texts, inBrowser)
    }

    private fun collect(
        node: AccessibilityNodeInfo?, out: MutableList<String>, urlBar: Array<String?>, inBrowser: Boolean,
        depth: Int, count: IntArray
    ) {
        if (node == null || depth > MAX_DEPTH || count[0] > MAX_NODES) return
        count[0]++
        if (node.isPassword) return                       // never read password fields (or their children)
        if (inBrowser && urlBar[0] == null) {
            val id = node.viewIdResourceName?.substringAfter(":id/")
            if (id != null && URL_BAR_IDS.any { id.equals(it, true) || id.contains(it, true) } && !node.text.isNullOrBlank()) {
                // skip while the user is typing in the bar
                if (!(node.isFocused && node.isEditable)) urlBar[0] = node.text.toString().trim()
                return
            }
        }
        if (node.isVisibleToUser && !(node.isEditable && node.isFocused)) {   // never read what the user is typing
            val t = node.text?.toString()?.trim()
            if (!t.isNullOrEmpty() && t.length >= 8) out.add(t.take(2000))
            else {
                val d = node.contentDescription?.toString()?.trim()
                if (!d.isNullOrEmpty() && d.length >= 20) out.add(d.take(1000))
            }
        }
        for (i in 0 until node.childCount) {
            val c = try { node.getChild(i) } catch (_: Throwable) { null } ?: continue
            collect(c, out, urlBar, inBrowser, depth + 1, count)
            if (Build.VERSION.SDK_INT < 33) {
                @Suppress("DEPRECATION")
                try { c.recycle() } catch (_: Throwable) {}
            }
        }
    }

    private fun norm(s: String) = s.lowercase(Locale.ROOT).replace(Regex("\\s+"), " ").trim()
    private fun keyOf(s: String): String {
        val body = s.substringAfter(":\n", s)       // notifications: hash the message body, not "From X:"
        val n = norm(body)
        return "t:" + n.hashCode().toString(16) + ":" + n.length
    }

    private fun isFresh(key: String, now: Long): Boolean {
        val t = seen[key]
        return t == null || now - t > SEEN_TTL_MS
    }

    private fun wordCount(s: String) = s.split(Regex("\\s+")).count { it.length > 1 }

    /** Worker thread. Each chunk = one message / bubble / notification line. */
    private fun process(pkg: String, raw: List<String>, inBrowser: Boolean) {
        val now = SystemClock.elapsedRealtime()
        val fresh = ArrayList<Job>()
        raw.distinct().forEachIndexed { idx, text ->
            val key = keyOf(text)
            if (!isFresh(key, now)) return@forEachIndexed
            seen[key] = now
            val local = ScamRules.check(text)
            // instant warning when the on-device rules are confident
            if (local.score >= LOCAL_WARN) alert(key, scam = true, hasLink = local.urls.isNotEmpty(), reason = local.topReason, text = text)
            val messageLike = (text.length >= 20 && wordCount(text) >= 4) || local.urls.isNotEmpty()
            val eligible = if (inBrowser) local.score >= 20 else messageLike
            if (!eligible) return@forEachIndexed
            val host = local.urls.firstOrNull()?.let { ScamRules.hostOf(it) }
            // newer chat messages sit lower on screen: later index = higher priority
            val prio = local.score + (if (local.urls.isNotEmpty()) 30 else 0) + idx.coerceAtMost(40) / 4
            fresh.add(Job(key, text.take(1500), local, pkg, prio, if (host != null) "h:$host" else key))
        }
        fresh.sortedByDescending { it.priority }.take(PER_SCAN_MAX).forEach { enqueue(it) }
    }

    // ---------- browser: close scam sites ----------

    private fun checkBrowserUrl(pkg: String, barText: String) {
        val withScheme = if (barText.contains("://")) barText else "https://$barText"
        val host = ScamRules.hostOf(withScheme)
        if (host.isEmpty() || !host.contains('.') || host.contains(' ')) return
        val now = SystemClock.elapsedRealtime()
        val last = lastBrowserHost[pkg]
        if (last != null && last.first == host && now - last.second < 10_000) return
        lastBrowserHost[pkg] = host to now
        if (ScamRules.isOfficialHost(host)) return
        val local = ScamRules.check(withScheme)
        val key = "url:$host"
        if (local.score >= LOCAL_WARN) {
            seen[key] = now
            onScamSite(pkg, host, local.topReason, local.brand)
            return
        }
        if (local.score >= LOCAL_CAREFUL) alert(key, scam = false, hasLink = true, reason = local.topReason, text = withScheme)
        if (!isFresh(key, now)) return
        seen[key] = now
        enqueue(Job(key, "Website address open in the phone's browser: $withScheme", local, pkg, 200, "h:$host", browserHost = host))
    }

    private fun onScamSite(pkg: String, host: String, reason: String, brand: String?) {
        if (ScamRules.isOfficialHost(host)) return
        val now = SystemClock.elapsedRealtime()
        if (!Prefs.autoClose(this)) {
            alert("url:$host", scam = true, hasLink = true, reason = reason, text = "https://$host")
            return
        }
        val prev = closedAt[host]
        if (prev != null && now - prev < 4000) return
        closedAt[host] = now
        val official = brand?.let { ScamRules.officialSite[it] }
        main.post {
            performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            main.postDelayed({
                worker.post {
                    // if BACK didn't leave the page, go HOME
                    val root = try { rootInActiveWindow } catch (_: Throwable) { null }
                    val stillThere = root?.packageName?.toString() == pkg && run {
                        val bar = arrayOfNulls<String>(1)
                        collect(root, ArrayList(), bar, true, 0, intArrayOf(0))
                        bar[0]?.let { ScamRules.hostOf(if (it.contains("://")) it else "https://$it") } == host
                    }
                    main.post {
                        if (stillThere) performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
                        main.postDelayed({ openSafe(pkg, host, reason, brand, official) }, if (stillThere) 350 else 50)
                    }
                }
            }, 650)
        }
    }

    /** Main thread. */
    private fun openSafe(pkg: String, host: String, reason: String, brand: String?, official: String?) {
        var opened = false
        if (official != null) {
            val view = Intent(Intent.ACTION_VIEW, Uri.parse(official)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            opened = try { startActivity(Intent(view).setPackage(pkg)); true } catch (_: Throwable) {
                try { startActivity(view); true } catch (_: Throwable) { false }
            }
            if (opened) {
                banner.show("closed:$host", "Sniff closed a dangerous site",
                    "$host was pretending to be ${brand?.uppercase(Locale.ROOT)}. I opened the real site.", true,
                    onTap = { openBlocked(host, reason, official) })
            }
        }
        if (!opened) openBlocked(host, reason, official)
    }

    private fun openBlocked(host: String, reason: String, official: String?) {
        try {
            startActivity(Intent(this, BlockedActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
                .putExtra(BlockedActivity.EXTRA_HOST, host)
                .putExtra(BlockedActivity.EXTRA_REASON, reason)
                .putExtra(BlockedActivity.EXTRA_REAL, official))
        } catch (_: Throwable) {
            alert("url:$host", scam = true, hasLink = true, reason = reason, text = "https://$host")
        }
    }

    // ---------- AI queue (worker thread) ----------

    private fun enqueue(job: Job) {
        if (queue.any { it.key == job.key }) return
        if (queue.size >= QUEUE_MAX) {
            val worst = queue.minByOrNull { it.priority } ?: return
            if (worst.priority >= job.priority) return
            queue.remove(worst)
        }
        queue.add(job)
        pump()
    }

    private fun pump() {
        worker.removeCallbacks(pumpLater)
        val now = SystemClock.elapsedRealtime()
        while (sentTimes.isNotEmpty() && now - sentTimes.first() > 60_000) sentTimes.removeFirst()
        var wakeAt = Long.MAX_VALUE
        while (active < SniffApi.MAX_CONCURRENT && queue.isNotEmpty()) {
            if (sentTimes.size >= BUDGET_PER_MIN) { wakeAt = minOf(wakeAt, sentTimes.first() + 60_000); break }
            val ready = queue.filter { now - (lastBySource[it.source] ?: 0L) >= SOURCE_GAP_MS }
            if (ready.isEmpty()) {
                wakeAt = minOf(wakeAt, queue.minOf { (lastBySource[it.source] ?: 0L) + SOURCE_GAP_MS })
                break
            }
            val job = ready.maxByOrNull { it.priority }!!
            queue.remove(job)
            lastBySource[job.source] = now
            if (lastBySource.size > 500) lastBySource.entries.removeAll { now - it.value > 60_000 }
            sentTimes.addLast(now)
            active++
            SniffApi.checkAsync(job.text) { v ->
                worker.post {
                    active--
                    onVerdict(job, v)
                    pump()
                }
            }
        }
        if (queue.isNotEmpty() && wakeAt != Long.MAX_VALUE) worker.postDelayed(pumpLater, (wakeAt - now).coerceIn(50, 60_000))
    }

    private fun onVerdict(job: Job, v: SniffApi.Verdict?) {
        val hasLink = job.local.urls.isNotEmpty()
        when {
            v == null -> {
                // offline / timeout: fall back to the local rules (>=60 already warned instantly)
                if (job.local.score in LOCAL_CAREFUL until LOCAL_WARN) alert(job.key, false, hasLink, job.local.topReason, job.text)
            }
            v.risky -> {
                if (job.browserHost != null && v.scam) {
                    onScamSite(job.pkg, job.browserHost, v.reason.ifBlank { job.local.topReason }, job.local.brand)
                } else {
                    alert(job.key, v.scam, hasLink || job.browserHost != null, v.reason, job.text)
                }
            }
            else -> {
                // AI says safe: keep only a very confident local warning (as "be careful"), otherwise clear it
                if (job.local.score >= 75) alert(job.key, false, hasLink, job.local.topReason, job.text)
                else main.post { banner.dismissIfShowing(job.key) }
            }
        }
    }

    // ---------- alerts ----------

    private fun alert(key: String, scam: Boolean, hasLink: Boolean, reason: String, text: String) {
        val title = when {
            scam && hasLink -> "Don't click this link"
            scam -> "This is a scam. Don't reply."
            else -> "Be careful"
        }
        var r = reason.ifBlank { "Sniff thinks this may be a scam." }.replace('\n', ' ').trim()
        if (r.length > 120) r = r.take(117).trimEnd() + "…"
        val snippet = text.take(1500)
        val ctx = this
        banner.show(key, title, r, scam,
            onTap = {
                try {
                    startActivity(Intent(ctx, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                        .putExtra(MainActivity.EXTRA_TEXT, snippet))
                } catch (_: Throwable) {}
            },
            onFail = { Alerts.warn(ctx, title, r, snippet, scam) })
    }
}
