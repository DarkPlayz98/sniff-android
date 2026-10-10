package com.sniff.app

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory

/**
 * Calls the live Sniff checker (POST /api/sniff, Groq behind it, ~0.6-1.5 s).
 * One shared 3-thread executor; HttpURLConnection reuses the TLS keep-alive pool because
 * every response body is read to the end and the connection is never disconnect()ed.
 * Only the given text is sent; nothing is stored.
 */
object SniffApi {
    const val ENDPOINT = "https://sniff-orpin.vercel.app/api/sniff"
    private const val TIMEOUT_MS = 6000
    const val MAX_CONCURRENT = 3

    val executor = Executors.newFixedThreadPool(MAX_CONCURRENT, ThreadFactory { r ->
        Thread(r, "sniff-ai").apply { isDaemon = true; priority = Thread.NORM_PRIORITY }
    })

    init { System.setProperty("http.keepAlive", "true"); System.setProperty("http.maxConnections", "5") }

    data class Verdict(
        val verdict: String,        // SCAM | SUSPICIOUS | LOOKS_SAFE
        val score: Int,
        val scamType: String,
        val summary: String,
        val flags: List<String>,
        val whatToDo: List<String>
    ) {
        val risky: Boolean get() = verdict == "SCAM" || verdict == "SUSPICIOUS"
        val scam: Boolean get() = verdict == "SCAM"
        val reason: String get() = summary.ifBlank { flags.firstOrNull() ?: scamType }
    }

    /** Opens the TLS connection early so the first real check doesn't pay the handshake. */
    fun warmUp() {
        executor.execute {
            try {
                val c = URL("https://sniff-orpin.vercel.app/robots.txt").openConnection() as HttpURLConnection
                c.connectTimeout = TIMEOUT_MS; c.readTimeout = TIMEOUT_MS
                c.inputStream.use { it.readBytes() }
            } catch (_: Throwable) {}
        }
    }

    /** Async check; [cb] runs on an executor thread with null on any failure/timeout. */
    fun checkAsync(message: String, cb: (Verdict?) -> Unit) {
        executor.execute { cb(check(message)) }
    }

    /** Blocking. Call off the main thread. Returns null on any failure. */
    fun check(message: String): Verdict? {
        return try {
            val conn = (URL(ENDPOINT).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                setRequestProperty("Connection", "keep-alive")
                setRequestProperty("User-Agent", "SniffAndroid/0.3")
            }
            val body = JSONObject().put("message", message.take(4000)).toString().toByteArray(Charsets.UTF_8)
            conn.setFixedLengthStreamingMode(body.size)
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            if (code !in 200..299) {
                try { conn.errorStream?.use { it.readBytes() } } catch (_: Throwable) {}
                return null
            }
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
        }
    }
}
