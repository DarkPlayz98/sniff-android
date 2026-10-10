package com.sniff.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Recent warnings, kept only on this phone (app-private file, max 200, newest first).
 * Every call is synchronized; the file is small (text is capped at 600 chars per entry).
 */
object History {
    private const val FILE = "history.json"
    private const val MAX = 200

    data class Entry(
        val key: String,
        val time: Long,
        val pkg: String,
        val kind: String,        // "scam" | "sus"
        val title: String,
        val reason: String,
        val text: String,
        val host: String?,
        val sender: String?
    )

    @Volatile private var cache: MutableList<Entry>? = null

    private fun file(ctx: Context) = File((ctx.applicationContext ?: ctx).filesDir, FILE)

    @Synchronized private fun load(ctx: Context): MutableList<Entry> {
        cache?.let { return it }
        val out = ArrayList<Entry>()
        try {
            val f = file(ctx)
            if (f.exists()) {
                val a = JSONArray(f.readText())
                for (i in 0 until a.length()) {
                    val o = a.optJSONObject(i) ?: continue
                    out.add(Entry(
                        o.optString("k"), o.optLong("t"), o.optString("p"), o.optString("v", "scam"),
                        o.optString("ti"), o.optString("r"), o.optString("x"),
                        o.optString("h").ifEmpty { null }, o.optString("s").ifEmpty { null }
                    ))
                }
            }
        } catch (_: Throwable) {}
        cache = out
        return out
    }

    @Synchronized private fun save(ctx: Context, list: List<Entry>) {
        try {
            val a = JSONArray()
            for (e in list) a.put(JSONObject()
                .put("k", e.key).put("t", e.time).put("p", e.pkg).put("v", e.kind)
                .put("ti", e.title).put("r", e.reason).put("x", e.text)
                .put("h", e.host ?: "").put("s", e.sender ?: ""))
            val f = file(ctx)
            val tmp = File(f.parentFile, "$FILE.tmp")
            tmp.writeText(a.toString())
            if (!tmp.renameTo(f)) { f.writeText(a.toString()); tmp.delete() }
        } catch (_: Throwable) {}
    }

    /**
     * Adds (or updates in place, keeping the original time) a warning.
     * Returns true when this key is new, so callers count each scam only once.
     */
    @Synchronized fun add(ctx: Context, e: Entry): Boolean {
        val list = load(ctx)
        val idx = list.indexOfFirst { it.key == e.key }
        val isNew = idx < 0
        if (!isNew) {
            val old = list.removeAt(idx)
            list.add(0, e.copy(time = old.time))
        } else {
            list.add(0, e.copy(text = e.text.take(600)))
            while (list.size > MAX) list.removeAt(list.size - 1)
        }
        save(ctx, list)
        return isNew
    }

    @Synchronized fun all(ctx: Context): List<Entry> = ArrayList(load(ctx))

    /** Removes the entry with [key]; returns it (or null if there was none). */
    @Synchronized fun remove(ctx: Context, key: String): Entry? {
        val list = load(ctx)
        val idx = list.indexOfFirst { it.key == key }
        if (idx < 0) return null
        val e = list.removeAt(idx)
        save(ctx, list)
        return e
    }

    @Synchronized fun clear(ctx: Context) {
        cache = ArrayList()
        try { file(ctx).delete() } catch (_: Throwable) {}
    }
}
