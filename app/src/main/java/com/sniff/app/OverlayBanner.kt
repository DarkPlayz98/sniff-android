package com.sniff.app

import android.content.Context
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.TextView

/** Small dismissible banner at the top of the screen. Uses TYPE_ACCESSIBILITY_OVERLAY (no extra permission). */
class OverlayBanner(private val ctx: Context) {
    private val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private var view: View? = null
    private val hide = Runnable { dismiss() }

    private fun dp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, ctx.resources.displayMetrics).toInt()

    fun show(title: String, reason: String, danger: Boolean) {
        handler.post {
            dismiss()
            val bg = GradientDrawable().apply {
                cornerRadius = dp(14f).toFloat()
                setColor(if (danger) 0xFFD92D20.toInt() else 0xFFB54708.toInt())
            }
            val root = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                background = bg
                setPadding(dp(16f), dp(12f), dp(8f), dp(12f))
                elevation = dp(6f).toFloat()
            }
            val texts = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
            texts.addView(TextView(ctx).apply {
                text = title
                setTextColor(0xFFFFFFFF.toInt())
                textSize = 16f
                typeface = Typeface.DEFAULT_BOLD
            })
            texts.addView(TextView(ctx).apply {
                text = reason
                setTextColor(0xFFFFFFFF.toInt())
                textSize = 13f
                maxLines = 3
            })
            root.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            root.addView(TextView(ctx).apply {
                text = "✕"
                contentDescription = "Dismiss"
                setTextColor(0xFFFFFFFF.toInt())
                textSize = 18f
                setPadding(dp(12f), dp(4f), dp(12f), dp(4f))
                setOnClickListener { dismiss() }
            })
            root.setOnClickListener { dismiss() }

            val lp = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.TOP
                x = 0
                y = dp(36f)
                horizontalMargin = 0.03f
            }
            try {
                wm.addView(root, lp)
                view = root
                handler.postDelayed(hide, 6000)
            } catch (_: Throwable) {
                view = null
            }
        }
    }

    fun dismiss() {
        handler.removeCallbacks(hide)
        view?.let { try { wm.removeView(it) } catch (_: Throwable) {} }
        view = null
    }
}
