package com.sniff.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast

/** Shown after Sniff closes a dangerous site in a browser. */
class BlockedActivity : Activity() {

    companion object {
        const val EXTRA_HOST = "host"
        const val EXTRA_REASON = "reason"
        const val EXTRA_REAL = "real"
    }

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(Lang.wrap(newBase)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_blocked)
        bind(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        bind(intent)
    }

    private fun bind(i: Intent) {
        val host = i.getStringExtra(EXTRA_HOST).orEmpty()
        val reason = i.getStringExtra(EXTRA_REASON).orEmpty()
        val real = i.getStringExtra(EXTRA_REAL)
        findViewById<TextView>(R.id.b_domain).text = host.ifEmpty { getString(R.string.blocked_unknown) }
        findViewById<TextView>(R.id.b_reason).text = reason.ifBlank { getString(R.string.blocked_reason_default) }
        val realBtn = findViewById<Button>(R.id.b_real)
        if (real.isNullOrBlank()) {
            realBtn.visibility = View.GONE
        } else {
            realBtn.visibility = View.VISIBLE
            realBtn.setOnClickListener {
                try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(real)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } catch (_: Throwable) {}
                finish()
            }
        }
        findViewById<Button>(R.id.b_safe).setOnClickListener { goHome() }
        findViewById<Button>(R.id.b_call).setOnClickListener { dial1930(this) }
        findViewById<Button>(R.id.b_report).setOnClickListener {
            try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://cybercrime.gov.in"))) } catch (_: Throwable) {}
        }
        val trust = findViewById<TextView>(R.id.b_trust)
        if (host.isEmpty() || Prefs.isTrustedHost(Prefs.trusted(this), host)) {
            trust.visibility = View.GONE
        } else {
            trust.visibility = View.VISIBLE
            trust.text = getString(R.string.trust_site, host)
            trust.setOnClickListener {
                Prefs.addTrusted(this, Prefs.SITE + host.lowercase().removePrefix("www."))
                Toast.makeText(this, getString(R.string.trusted_done, host), Toast.LENGTH_LONG).show()
                trust.visibility = View.GONE
            }
        }
    }

    private fun goHome() {
        try {
            startActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: Throwable) {}
        finish()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() { goHome() }
}
