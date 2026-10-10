package com.sniff.app

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/** App-chosen language (English / Hindi / Telugu) for the UI, banner and verdict strings. */
object Lang {
    val CODES = listOf("en", "hi", "te")
    val NAMES = listOf("English", "हिन्दी", "తెలుగు")

    /** A context whose resources use the language picked in Sniff, whatever the phone's language is. */
    fun wrap(base: Context): Context {
        val code = try { Prefs.lang(base) } catch (_: Throwable) { "en" }
        val locale = Locale.forLanguageTag(code)
        val cfg = Configuration(base.resources.configuration)
        cfg.setLocale(locale)
        cfg.setLayoutDirection(locale)
        return base.createConfigurationContext(cfg)
    }
}
