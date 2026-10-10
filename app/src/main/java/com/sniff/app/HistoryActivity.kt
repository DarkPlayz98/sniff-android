package com.sniff.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.os.Bundle
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Recent warnings, stored only on this phone. Tap one to see details, trust it or get help. */
class HistoryActivity : Activity() {

    private lateinit var list: LinearLayout
    private lateinit var empty: TextView
    private val labels = HashMap<String, String>()

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(Lang.wrap(newBase)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_list)
        findViewById<TextView>(R.id.l_title).setText(R.string.history)
        findViewById<View>(R.id.l_back).setOnClickListener { finish() }
        list = findViewById(R.id.l_list)
        empty = findViewById(R.id.l_empty)
        empty.setText(R.string.history_empty)
        findViewById<Button>(R.id.l_action).apply {
            setText(R.string.clear_all)
            setOnClickListener {
                AlertDialog.Builder(this@HistoryActivity)
                    .setMessage(R.string.clear_history_q)
                    .setPositiveButton(R.string.delete) { _, _ -> History.clear(this@HistoryActivity); render() }
                    .setNegativeButton(R.string.dialog_cancel, null)
                    .show()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun appLabel(pkg: String): String {
        if (pkg.isEmpty()) return ""
        return labels.getOrPut(pkg) {
            try {
                val pm = packageManager
                pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
            } catch (_: PackageManager.NameNotFoundException) { pkg } catch (_: Throwable) { pkg }
        }
    }

    private fun render() {
        // keep the empty-state view (child 0), drop old rows
        while (list.childCount > 1) list.removeViewAt(1)
        val items = History.all(this)
        empty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        findViewById<View>(R.id.l_action).visibility = if (items.isEmpty()) View.GONE else View.VISIBLE
        val inf = LayoutInflater.from(this)
        for (e in items) {
            val row = inf.inflate(R.layout.item_history, list, false)
            val scam = e.kind == "scam"
            val color = getColor(if (scam) R.color.danger else R.color.warn)
            row.findViewById<View>(R.id.h_dot).backgroundTintList = ColorStateList.valueOf(color)
            row.findViewById<TextView>(R.id.h_kind).apply {
                setText(if (scam) R.string.kind_scam else R.string.kind_sus)
                setTextColor(color)
            }
            val time = DateUtils.getRelativeTimeSpanString(e.time, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS,
                DateUtils.FORMAT_ABBREV_RELATIVE)
            val app = appLabel(e.pkg)
            row.findViewById<TextView>(R.id.h_meta).text =
                if (app.isNotEmpty()) "$time · ${getString(R.string.from_app, app)}" else time
            row.findViewById<TextView>(R.id.h_reason).text = e.reason.ifBlank { e.title }
            row.findViewById<TextView>(R.id.h_text).text = e.text.replace(Regex("\\s+"), " ").trim()
            row.setOnClickListener {
                startActivity(Intent(this, MainActivity::class.java)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    .putExtra(MainActivity.EXTRA_TEXT, e.text)
                    .putExtra(MainActivity.EXTRA_HOST, e.host)
                    .putExtra(MainActivity.EXTRA_SENDER, e.sender))
                finish()
            }
            row.setOnLongClickListener {
                AlertDialog.Builder(this)
                    .setMessage(e.reason.ifBlank { e.title })
                    .setPositiveButton(R.string.delete) { _, _ -> History.remove(this, e.key); render() }
                    .setNegativeButton(R.string.dialog_cancel, null)
                    .show()
                true
            }
            list.addView(row)
        }
    }
}
