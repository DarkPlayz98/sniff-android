package com.sniff.app

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Calls the live Sniff checker. Only the given text is sent; nothing is stored. */
object SniffApi {
    const val ENDPOINT = "https://sniff-orpin.vercel.app/api/sniff"

    data class Verdict(
        val verdict: String,        // SCAM | SUSPICIOUS | LOOKS_SAFE
        val score: Int,
        val scamType: String,
        val summary: String,
        val flags: List<String>,
        val whatToDo: List<String>
    ) {
        val risky: Boolean get() = verdict == "SCAM" || verdict == "SUSPICIOUS"
        val reason: String get() = summary.ifBlank { flags.firstOrNull() ?: scamType }
    }

    /** Blocking. Call off the main thread. Returns null on any failure. */
    fun check(message: String): Verdict? {
        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(ENDPOINT).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 8000
                readTimeout = 25000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("User-Agent", "SniffAndroid/1")
            }
            val body = JSONObject().put("message", message.take(4000)).toString()
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (conn.responseCode !in 200..299) return null
            val txt = conn.inputStream.bufferedReader().use { it.readText() }
            val j = JSONObject(txt)
            val flags = ArrayList<String>()
            j.optJSONArray("red_flags")?.let { a ->
                for (i in 0 until a.length()) {
                    val f = a.optJSONObject(i) ?: continue
                    val t = f.optString("title")
                    val e = f.optString("explanation")
                    flags.add(if (e.isNotBlank()) "$t: $e" else t)
                }
            }
            val todo = ArrayList<String>()
            j.optJSONArray("what_to_do")?.let { a -> for (i in 0 until a.length()) todo.add(a.optString(i)) }
            Verdict(
                verdict = j.optString("verdict", "LOOKS_SAFE").uppercase(),
                score = j.optInt("score", 0),
                scamType = j.optString("scam_type", ""),
                summary = j.optString("summary", ""),
                flags = flags,
                whatToDo = todo
            )
        } catch (_: Throwable) {
            null
        } finally {
            conn?.disconnect()
        }
    }
}
