package com.sniff.app

import android.content.ComponentName
import android.content.Context
import android.content.SharedPreferences
import android.service.quicksettings.TileService
import java.util.Locale

/** All on-device settings, counters and the trusted list. Nothing here ever leaves the phone. */
object Prefs {
    private const val FILE = "sniff"
    private const val AUTO_CLOSE = "auto_close"
    private const val PAUSED_UNTIL = "paused_until"     // 0 = protecting, Long.MAX_VALUE = until turned back on
    private const val LANG = "lang"
    private const val CHECKED = "count_checked"
    private const val BLOCKED = "count_blocked"
    private const val TRUSTED = "trusted"               // entries: "site:example.com" / "sender:Name"

    const val SITE = "site:"
    const val SENDER = "sender:"

    private fun sp(ctx: Context): SharedPreferences = (ctx.applicationContext ?: ctx).getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun autoClose(ctx: Context): Boolean = sp(ctx).getBoolean(AUTO_CLOSE, true)
    fun setAutoClose(ctx: Context, on: Boolean) { sp(ctx).edit().putBoolean(AUTO_CLOSE, on).apply() }

    /** Returns true the first time only. */
    @Synchronized fun markAskedNotifications(ctx: Context): Boolean {
        val p = sp(ctx)
        if (p.getBoolean("asked_notif", false)) return false
        p.edit().putBoolean("asked_notif", true).apply()
        return true
    }

    /** First-run setup screen was shown (it then only comes back from the home screen). */
    fun setupSeen(ctx: Context): Boolean = sp(ctx).getBoolean("setup_seen", false)
    fun markSetupSeen(ctx: Context) { sp(ctx).edit().putBoolean("setup_seen", true).apply() }

    // ---------- pause ----------
    fun pausedUntil(ctx: Context): Long = sp(ctx).getLong(PAUSED_UNTIL, 0L)
    fun isPaused(ctx: Context): Boolean = pausedUntil(ctx) > System.currentTimeMillis()
    fun pauseFor(ctx: Context, ms: Long) = setPausedUntil(ctx, System.currentTimeMillis() + ms)
    fun pauseForever(ctx: Context) = setPausedUntil(ctx, Long.MAX_VALUE)
    fun resume(ctx: Context) = setPausedUntil(ctx, 0L)
    private fun setPausedUntil(ctx: Context, t: Long) {
        sp(ctx).edit().putLong(PAUSED_UNTIL, t).apply()
        try {
            TileService.requestListeningState(ctx, ComponentName(ctx, SniffTileService::class.java))
        } catch (_: Throwable) {}
    }

    // ---------- language ----------
    /** "en", "hi" or "te". */
    fun lang(ctx: Context): String = sp(ctx).getString(LANG, "en") ?: "en"
    fun setLang(ctx: Context, l: String) { sp(ctx).edit().putString(LANG, l).apply() }

    // ---------- counters ----------
    fun checked(ctx: Context): Long = sp(ctx).getLong(CHECKED, 0L)
    fun blocked(ctx: Context): Long = sp(ctx).getLong(BLOCKED, 0L)
    @Synchronized fun addChecked(ctx: Context, n: Int) {
        if (n <= 0) return
        val p = sp(ctx); p.edit().putLong(CHECKED, p.getLong(CHECKED, 0L) + n).apply()
    }
    @Synchronized fun addBlocked(ctx: Context, delta: Int = 1) {
        val p = sp(ctx); p.edit().putLong(BLOCKED, (p.getLong(BLOCKED, 0L) + delta).coerceAtLeast(0L)).apply()
    }

    // ---------- trusted sites / senders ----------
    fun trusted(ctx: Context): Set<String> = HashSet(sp(ctx).getStringSet(TRUSTED, emptySet()) ?: emptySet())

    @Synchronized fun addTrusted(ctx: Context, entry: String) {
        val s = trusted(ctx).toMutableSet(); s.add(entry); sp(ctx).edit().putStringSet(TRUSTED, s).apply()
    }
    @Synchronized fun removeTrusted(ctx: Context, entry: String) {
        val s = trusted(ctx).toMutableSet(); s.remove(entry); sp(ctx).edit().putStringSet(TRUSTED, s).apply()
    }

    fun normSender(s: String) = s.trim().lowercase(Locale.ROOT).replace(Regex("\\s+"), " ")

    /** True when [host] (or a parent domain of it) is on the trusted list. */
    fun isTrustedHost(set: Set<String>, host: String): Boolean {
        var h = host.lowercase(Locale.ROOT).removePrefix("www.")
        while (h.contains('.')) {
            if ("$SITE$h" in set) return true
            h = h.substringAfter('.')
        }
        return false
    }

    fun isTrustedSender(set: Set<String>, sender: String?): Boolean =
        !sender.isNullOrBlank() && "$SENDER${normSender(sender)}" in set

    /** Prominent-disclosure consent for the Accessibility service (Google policy). */
    fun a11yConsent(ctx: Context): Boolean = sp(ctx).getBoolean("a11y_consent", false)
    fun setA11yConsent(ctx: Context, on: Boolean) { sp(ctx).edit().putBoolean("a11y_consent", on).apply() }
}
