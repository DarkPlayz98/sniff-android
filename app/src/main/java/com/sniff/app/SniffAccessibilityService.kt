package com.sniff.app

import android.accessibilityservice.AccessibilityService
import android.app.Notification
import android.content.Context
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
import android.view.inputmethod.InputMethodManager
import java.util.Locale

/**
 * Reads visible text and new notifications, splits them into message-sized chunks, runs the
 * on-device rules instantly and sends every NEW message/link to Sniff AI (deduped by content hash,
 * max 3 in flight, small priority queue). Confident local hits warn instantly; the AI verdict then
 * refines or replaces the warning. In browsers, a scam URL is closed (once per site) and a safe
 * page is opened. Only the warnings themselves are saved, on this phone (History).
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
        private const val CLOSE_TTL_MS = 30 * 60 * 1000L   // auto-close a given site at most once per 30 min
        private const val REALERT_MS = 6 * 60 * 60 * 1000L  // never re-show the same warning within 6 h
        private const val REFINE_MS = 30_000L                // ...except the AI refining a fresh local warning

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
        val priority: Int, val source: String, val browserHost: String? = null, val sender: String? = null
    )

    private val main = Handler(Looper.getMainLooper())
    private lateinit var workerThread: HandlerThread
    private lateinit var worker: Handler
    private lateinit var banner: OverlayBanner

    // worker-thread state only
    private val seen = object : LinkedHashMap<String, Long>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > SEEN_MAX
    }
    private val shownAt = object : LinkedHashMap<String, Long>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?) = size > 500
    }
    private val queue = ArrayList<Job>()
    private var active = 0
    private val lastBySource = HashMap<String, Long>()
    private val sentTimes = ArrayDeque<Long>()
    private val lastBrowserHost = HashMap<String, Pair<String, Long>>()
    private val closedAt = HashMap<String, Long>()
    private val againAt = HashMap<String, Long>()
    private var extraSkip: Set<String> = emptySet()   // keyboards + the home screen app on this phone
    private var extraSkipAt = 0L
    private var trusted: Set<String> = emptySet()
    private var trustedAt = 0L
    @Volatile private var firstPendingAt = 0L
    @Volatile private var destroyed = false

    // language-aware resources for banner text
    private var langCode: String? = null
    private var langCtx: Context? = null
    private fun str(): Context {
        val code = Prefs.lang(this)
        if (code != langCode || langCtx == null) { langCtx = Lang.wrap(this); langCode = code }
        return langCtx!!
    }

    private val scan = Runnable { firstPendingAt = 0L; scanNow() }
    private val pumpLater = Runnable { pump() }

    override fun onServiceConnected() {
        super.onServiceConnected()
        running = true
        destroyed = false
        workerThread = HandlerThread("sniff-scan").also { it.start() }
        worker = Handler(workerThread.looper)
        banner = OverlayBanner(this)
        Alerts.ensureChannel(this)
        SniffApi.warmUp()
        worker.post { refreshSkip(force = true) }
    }

    private fun isSkipped(pkg: String) = pkg == packageName || pkg in SKIP_PACKAGES || pkg in extraSkip

    /** Worker thread. Every keyboard installed on the phone and the default home screen are never read. */
    private fun refreshSkip(force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        if (!force && now - extraSkipAt < 10 * 60 * 1000L) return
        extraSkipAt = now
        val s = HashSet<String>()
        try {
            getSystemService(InputMethodManager::class.java)?.inputMethodList?.forEach { s.add(it.packageName) }
        } catch (_: Throwable) {}
        try {
            val home = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME)
            packageManager.resolveActivity(home, 0)?.activityInfo?.packageName?.let { if (it != "android") s.add(it) }
        } catch (_: Throwable) {}
        extraSkip = s
    }

    /** Worker thread. The trusted list, re-read at most every 2 s. */
    private fun trustedNow(): Set<String> {
        val now = SystemClock.elapsedRealtime()
        if (now - trustedAt > 2000) { trusted = Prefs.trusted(this); trustedAt = now }
        return trusted
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null || destroyed || !::worker.isInitialized) return
        val pkg = event.packageName?.toString() ?: return
        if (isSkipped(pkg)) return
        if (Prefs.isPaused(this)) return
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
        destroyed = true
        main.removeCallbacksAndMessages(null)
        if (::banner.isInitialized) banner.release()
        if (::worker.isInitialized) worker.removeCallbacksAndMessages(null)
        if (::workerThread.isInitialized) workerThread.quitSafely()
        super.onDestroy()
    }

    // ---------- notifications (incoming SMS / WhatsApp / mail) ----------

    private fun notificationChunks(event: AccessibilityEvent): List<String> {
        val out = ArrayList<String>()
        val n = event.parcelableData as? Notification
        if (n != null) {
            if (n.flags and (Notification.FLAG_ONGOING_EVENT or Notification.FLAG_FOREGROUND_SERVICE) != 0) return out
            if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return out      // the summary repeats the children
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
                    val senderCs = b.getCharSequence("sender")
                    val hasPerson = try { b.get("sender_person") != null } catch (_: Throwable) { false }
                    // MessagingStyle: no sender = a message the user wrote. Never warn about the user's own words.
                    if (senderCs == null && !hasPerson) continue
                    val s = senderCs?.toString()?.trim()?.ifEmpty { null } ?: title
                    if (t.isNotEmpty()) out.add(if (s.isNotEmpty()) "From $s:\n$t" else t)
                }
                if (out.isEmpty()) return out
            }
            if (out.isEmpty()) {
                val big = ex.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()?.trim()
                val txt = big?.ifEmpty { null } ?: ex.getCharSequence(Notification.EXTRA_TEXT)?.toString()?.trim()
                if (!txt.isNullOrEmpty()) out.add(if (title.isNotEmpty()) "From $title:\n$txt" else txt)
                ex.getCharSequenceArray(Notification.EXTRA_TEXT_LINES)?.takeLast(4)?.forEach { l ->
                    val s = l?.toString()?.trim()
                    if (!s.isNullOrEmpty()) out.add(s)
                }
            }
        }
        if (out.isEmpty() && n == null) {
            val t = event.text?.joinToString("\n") { it?.toString().orEmpty() }?.trim()
            if (!t.isNullOrEmpty()) out.add(t)
        }
        return out
    }

    private fun senderOf(text: String): String? =
        if (text.startsWith("From ") && text.contains(":\n")) text.substring(5, text.indexOf(":\n")).trim().ifEmpty { null } else null

    // ---------- screen scan (worker thread) ----------

    private fun scanNow() {
        if (destroyed || Prefs.isPaused(this)) return
        refreshSkip()
        val root = try { rootInActiveWindow } catch (_: Throwable) { null } ?: return
        try {
            val pkg = root.packageName?.toString() ?: return
            if (isSkipped(pkg)) return
            val inBrowser = isBrowser(pkg)
            val texts = ArrayList<String>()
            val urlBar = arrayOfNulls<String>(1)
            collect(root, texts, urlBar, inBrowser, 0, intArrayOf(0))
            if (inBrowser) {
                val bar = urlBar[0]
                if (bar != null) {
                    val host = barHost(bar)
                    // a trusted or well-known site: don't read its page text (news about scams etc. is not a scam)
                    if (host != null && (ScamRules.isOfficialHost(host) || Prefs.isTrustedHost(trustedNow(), host))) return
                    checkBrowserUrl(pkg, bar)
                }
            }
            if (texts.isNotEmpty()) process(pkg, texts, inBrowser)
        } finally {
            recycle(root)
        }
    }

    private fun recycle(n: AccessibilityNodeInfo?) {
        if (n != null && Build.VERSION.SDK_INT < 33) {
            @Suppress("DEPRECATION")
            try { n.recycle() } catch (_: Throwable) {}
        }
    }

    private fun barHost(bar: String): String? {
        val withScheme = if (bar.contains("://")) bar else "https://$bar"
        val host = ScamRules.hostOf(withScheme)
        return if (host.isEmpty() || !host.contains('.') || host.contains(' ')) null else host
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
        if (node.isEditable) return                       // never read text fields: that's the user's own typing/draft
        if (node.isVisibleToUser) {
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
            recycle(c)
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

    /** True when the user trusted every link in it, or its sender. */
    private fun isTrustedChunk(local: ScamRules.Result, sender: String?): Boolean {
        val set = trustedNow()
        if (set.isEmpty()) return false
        if (Prefs.isTrustedSender(set, sender)) return true
        if (local.urls.isEmpty()) return false
        return local.urls.all { u -> ScamRules.hostOf(u).let { h -> h.isNotEmpty() && Prefs.isTrustedHost(set, h) } }
    }

    /** Worker thread. Each chunk = one message / bubble / notification line. */
    private fun process(pkg: String, raw: List<String>, inBrowser: Boolean) {
        if (destroyed || Prefs.isPaused(this)) return
        val now = SystemClock.elapsedRealtime()
        val fresh = ArrayList<Job>()
        var checkedCount = 0
        raw.distinct().forEachIndexed { idx, text ->
            val key = keyOf(text)
            if (!isFresh(key, now)) return@forEachIndexed
            seen[key] = now
            val local = ScamRules.check(text)
            val sender = senderOf(text)
            if (isTrustedChunk(local, sender)) return@forEachIndexed
            val messageLike = (text.length >= 20 && wordCount(text) >= 4) || local.urls.isNotEmpty()
            if (messageLike) checkedCount++
            val host = local.badHost ?: local.urls.firstOrNull()?.let { ScamRules.hostOf(it) }
            // instant warning when the on-device rules are confident
            if (local.score >= LOCAL_WARN) alert(key, scam = true, hasLink = local.urls.isNotEmpty(), reason = local.topReason,
                text = text, pkg = pkg, host = host, sender = sender)
            val eligible = if (inBrowser) local.score >= 20 else messageLike
            if (!eligible) return@forEachIndexed
            // newer chat messages sit lower on screen: later index = higher priority
            val prio = local.score + (if (local.urls.isNotEmpty()) 30 else 0) + idx.coerceAtMost(40) / 4
            fresh.add(Job(key, text.take(1500), local, pkg, prio, if (host != null) "h:$host" else key, sender = sender))
        }
        if (checkedCount > 0) Prefs.addChecked(this, checkedCount)
        fresh.sortedByDescending { it.priority }.take(PER_SCAN_MAX).forEach { enqueue(it) }
    }

    // ---------- browser: close scam sites ----------

    private fun checkBrowserUrl(pkg: String, barText: String) {
        val withScheme = if (barText.contains("://")) barText else "https://$barText"
        val host = barHost(barText) ?: return
        val now = SystemClock.elapsedRealtime()
        val last = lastBrowserHost[pkg]
        if (last != null && last.first == host && now - last.second < 10_000) return
        lastBrowserHost[pkg] = host to now
        if (ScamRules.isOfficialHost(host) || Prefs.isTrustedHost(trustedNow(), host)) return
        val key = "url:$host"
        if (!isFresh(key, now)) {                 // each site is judged once per 30 min, then left alone...
            val closed = closedAt[host]
            if (closed != null && now - closed < CLOSE_TTL_MS) onScamSite(pkg, host, "", null)   // ...but a closed one gets a reminder
            return
        }
        seen[key] = now
        Prefs.addChecked(this, 1)
        val local = ScamRules.check(withScheme)
        if (local.score >= LOCAL_WARN) {
            onScamSite(pkg, host, local.topReason, local.brand)
            return
        }
        if (local.score >= LOCAL_CAREFUL) alert(key, scam = false, hasLink = true, reason = local.topReason,
            text = withScheme, pkg = pkg, host = host)
        enqueue(Job(key, "Website address open in the phone's browser: $withScheme", local, pkg, 200, "h:$host", browserHost = host))
    }

    /** Worker thread: host currently shown in [pkg]'s address bar, if [pkg] is in front. */
    private fun frontBrowserHost(pkg: String): String? {
        val root = try { rootInActiveWindow } catch (_: Throwable) { null } ?: return null
        try {
            if (root.packageName?.toString() != pkg) return null
            val bar = arrayOfNulls<String>(1)
            collect(root, ArrayList(), bar, true, 0, intArrayOf(0))
            return bar[0]?.let { barHost(it) }
        } finally { recycle(root) }
    }

    /** Worker thread. Closes a scam site at most once per [CLOSE_TTL_MS]; never a trusted/official one. */
    private fun onScamSite(pkg: String, host: String, reason: String, brand: String?) {
        if (destroyed || Prefs.isPaused(this)) return
        if (ScamRules.isOfficialHost(host) || Prefs.isTrustedHost(trustedNow(), host)) return
        val key = "url:$host"
        val now = SystemClock.elapsedRealtime()
        if (!Prefs.autoClose(this)) {
            alert(key, scam = true, hasLink = true, reason = reason, text = "https://$host", pkg = pkg, host = host)
            return
        }
        val prev = closedAt[host]
        if (prev != null && now - prev < CLOSE_TTL_MS) {
            // already closed once: remind (at most once a minute), but never fight the user with Back/Home again
            if (now - (againAt[host] ?: 0L) > 60_000L) {
                againAt[host] = now
                alert(key, scam = true, hasLink = true, reason = str().getString(R.string.banner_again), text = "https://$host",
                    pkg = pkg, host = host, force = true)
            }
            return
        }
        // the AI verdict can arrive seconds later: only act if that browser is still showing that site
        if (frontBrowserHost(pkg) != host) {
            alert(key, scam = true, hasLink = true, reason = reason, text = "https://$host", pkg = pkg, host = host)
            return
        }
        closedAt[host] = now
        if (closedAt.size > 200) closedAt.entries.removeAll { now - it.value > CLOSE_TTL_MS }
        record(key, pkg, "scam", str().getString(R.string.banner_closed), reason, "https://$host", host, null)
        val official = brand?.let { ScamRules.officialSite[it] }
        main.post {
            if (destroyed) return@post
            performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            main.postDelayed({
                if (destroyed) return@postDelayed
                worker.post {
                    // if BACK didn't leave the page, go HOME (once)
                    val stillThere = frontBrowserHost(pkg) == host
                    main.post {
                        if (destroyed) return@post
                        if (stillThere) performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
                        main.postDelayed({ if (!destroyed) openSafe(pkg, host, reason, brand, official) }, if (stillThere) 350 else 50)
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
                val r = str()
                banner.show("closed:$host", r.getString(R.string.banner_closed),
                    r.getString(R.string.banner_closed_body, host, brand?.uppercase(Locale.ROOT) ?: ""), true,
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
            alert("url:$host", scam = true, hasLink = true, reason = reason, text = "https://$host", pkg = "", host = host, force = true)
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
        if (destroyed) return
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
            val job = ready.maxByOrNull { it.priority } ?: break
            queue.remove(job)
            lastBySource[job.source] = now
            if (lastBySource.size > 500) lastBySource.entries.removeAll { now - it.value > 60_000 }
            sentTimes.addLast(now)
            active++
            SniffApi.checkAsync(job.text) { v ->
                val posted = try { worker.post { active--; onVerdict(job, v); pump() } } catch (_: Throwable) { false }
                if (!posted) active = (active - 1).coerceAtLeast(0)
            }
        }
        if (queue.isNotEmpty() && wakeAt != Long.MAX_VALUE) worker.postDelayed(pumpLater, (wakeAt - now).coerceIn(50, 60_000))
    }

    private fun onVerdict(job: Job, v: SniffApi.Verdict?) {
        if (destroyed || Prefs.isPaused(this)) return
        val hasLink = job.local.urls.isNotEmpty()
        val host = job.browserHost ?: job.local.badHost ?: job.local.urls.firstOrNull()?.let { ScamRules.hostOf(it) }
        when {
            v == null -> {
                // offline / timeout: fall back to the local rules (>=60 already warned instantly)
                if (job.local.score in LOCAL_CAREFUL until LOCAL_WARN)
                    alert(job.key, false, hasLink, job.local.topReason, job.text, job.pkg, host, job.sender)
            }
            v.risky -> {
                if (job.browserHost != null && v.scam) {
                    onScamSite(job.pkg, job.browserHost, v.reason.ifBlank { job.local.topReason }, job.local.brand)
                } else {
                    alert(job.key, v.scam, hasLink || job.browserHost != null, v.reason, job.text, job.pkg, host, job.sender)
                }
            }
            else -> {
                // AI says safe: keep only a very confident local warning (as "be careful"), otherwise clear it
                if (job.local.score >= 75) alert(job.key, false, hasLink, job.local.topReason, job.text, job.pkg, host, job.sender)
                else {
                    main.post { banner.dismissIfShowing(job.key) }
                    History.remove(this, job.key)?.let { if (it.kind == "scam") Prefs.addBlocked(this, -1) }
                }
            }
        }
    }

    // ---------- alerts ----------

    /** Saves the warning to on-device History; counts a scam once per key. Worker thread. */
    private fun record(key: String, pkg: String, kind: String, title: String, reason: String, text: String, host: String?, sender: String?) {
        try {
            val isNew = History.add(this, History.Entry(key, System.currentTimeMillis(), pkg, kind, title, reason, text, host, sender))
            if (isNew && kind == "scam") Prefs.addBlocked(this)
        } catch (_: Throwable) {}
    }

    private fun alert(
        key: String, scam: Boolean, hasLink: Boolean, reason: String, text: String,
        pkg: String, host: String? = null, sender: String? = null, force: Boolean = false
    ) {
        if (destroyed || Prefs.isPaused(this)) return
        val now = SystemClock.elapsedRealtime()
        val first = shownAt[key]
        // never nag: one warning per thing, but let the AI refine a warning it just replaced
        if (!force && first != null && now - first in REFINE_MS..REALERT_MS) return
        if (first == null || now - first > REALERT_MS) shownAt[key] = now
        val r0 = str()
        val title = r0.getString(when {
            scam && hasLink -> R.string.banner_link
            scam -> R.string.banner_scam
            else -> R.string.banner_careful
        })
        var r = reason.ifBlank { r0.getString(R.string.banner_reason_default) }.replace('\n', ' ').trim()
        if (r.length > 120) r = r.take(117).trimEnd() + "…"
        val snippet = text.take(1500)
        val reasonFinal = r
        if (Looper.myLooper() == worker.looper) record(key, pkg, if (scam) "scam" else "sus", title, reasonFinal, snippet, host, sender)
        else worker.post { record(key, pkg, if (scam) "scam" else "sus", title, reasonFinal, snippet, host, sender) }
        val ctx = this
        banner.show(key, title, r, scam,
            onTap = {
                try {
                    startActivity(Intent(ctx, MainActivity::class.java)
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                        .putExtra(MainActivity.EXTRA_TEXT, snippet)
                        .putExtra(MainActivity.EXTRA_HOST, host)
                        .putExtra(MainActivity.EXTRA_SENDER, sender))
                } catch (_: Throwable) {}
            },
            onFail = { Alerts.warn(ctx, title, reasonFinal, snippet, scam) })
    }
}
