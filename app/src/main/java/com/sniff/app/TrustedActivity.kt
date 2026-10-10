package com.sniff.app

import android.app.Activity
import android.content.Context
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Sites and senders the user marked as safe. Sniff never warns about these. */
class TrustedActivity : Activity() {

    private lateinit var list: LinearLayout
    private lateinit var empty: TextView

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(Lang.wrap(newBase)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_list)
        findViewById<TextView>(R.id.l_title).setText(R.string.trusted)
        findViewById<View>(R.id.l_back).setOnClickListener { finish() }
        findViewById<Button>(R.id.l_action).visibility = View.GONE
        list = findViewById(R.id.l_list)
        empty = findViewById(R.id.l_empty)
        empty.setText(R.string.trusted_empty)
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        while (list.childCount > 1) list.removeViewAt(1)
        val items = Prefs.trusted(this).sorted()
        empty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        val inf = LayoutInflater.from(this)
        for (entry in items) {
            val row = inf.inflate(R.layout.item_trusted, list, false)
            val isSite = entry.startsWith(Prefs.SITE)
            row.findViewById<TextView>(R.id.t_kind).setText(if (isSite) R.string.trusted_site_label else R.string.trusted_sender_label)
            row.findViewById<TextView>(R.id.t_value).text = entry.substringAfter(':')
            row.findViewById<Button>(R.id.t_remove).setOnClickListener {
                Prefs.removeTrusted(this, entry)
                render()
            }
            list.addView(row)
        }
    }
}
