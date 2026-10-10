package com.sniff.app

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Outline
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.ViewOutlineProvider
import android.view.WindowManager
import android.view.animation.AccelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.abs

/**
 * Minimal "liquid glass" warning banner at the top of the screen.
 * Translucent white card (24dp radius), hairline white edge, soft shadow, small Sniff mark,
 * one bold line + one muted reason, coloured accent dot. No blur of the screen behind it.
 * Slides/fades in, auto-dismisses after 6 s, swipe up or tap X to dismiss, tap for details.
 * Uses TYPE_ACCESSIBILITY_OVERLAY (no extra permission).
 */
class OverlayBanner(
    private val ctx: Context,
    /** TYPE_ACCESSIBILITY_OVERLAY from the service; TYPE_APPLICATION_OVERLAY (needs "display over other apps") from the app. */
    private val windowType: Int = WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY
) {
    private val wm = ctx.getSystemService(Context.WINDOW_SERVICE) as WindowManager
    private val handler = Handler(Looper.getMainLooper())
    private var root: View? = null
    private var titleView: TextView? = null
    private var reasonView: TextView? = null
    private var dotView: View? = null
    private var currentKey: String? = null
    private var onTap: (() -> Unit)? = null
    private val hide = Runnable { dismiss(animated = true) }
    @Volatile private var released = false

    private fun dp(v: Float) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, ctx.resources.displayMetrics)
    private fun dpi(v: Float) = dp(v).toInt()

    val showingKey: String? get() = currentKey

    private fun dot(scam: Boolean) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(if (scam) 0xFFE5383B.toInt() else 0xFFF5A524.toInt())
    }

    /**
     * Shows (or, when [key] is already on screen, updates in place) the banner.
     * [onFail] runs if the overlay can't be added, so the caller can fall back to a notification.
     */
    fun show(key: String, title: String, reason: String, scam: Boolean, onTap: () -> Unit, onFail: () -> Unit = {}) {
        if (released) return
        handler.post {
            if (released) return@post
            this.onTap = onTap
            if (root != null && currentKey == key) {
                titleView?.text = title
                reasonView?.text = reason
                dotView?.background = dot(scam)
                handler.removeCallbacks(hide)
                handler.postDelayed(hide, AUTO_DISMISS_MS)
                return@post
            }
            dismiss(animated = false)
            try {
                addBanner(key, title, reason, scam)
            } catch (_: Throwable) {
                // BadTokenException / service gone: never leave a half-added window behind
                root?.let { v -> try { wm.removeViewImmediate(v) } catch (_: Throwable) {} }
                root = null; currentKey = null; titleView = null; reasonView = null; dotView = null
                this.onTap = null
                onFail()
            }
        }
    }

    fun dismissIfShowing(key: String) {
        handler.post { if (currentKey == key) dismiss(animated = true) }
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun addBanner(key: String, title: String, reason: String, scam: Boolean) {
        val radius = dp(24f)
        val glass = GradientDrawable().apply {
            cornerRadius = radius
            setColor(0xEDFBFAF8.toInt())   // frosted white glass card, no screen blur
            setStroke(maxOf(1, dpi(0.75f)), 0xE6FFFFFF.toInt())
        }
        val card = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = glass
            setPadding(dpi(14f), dpi(12f), dpi(6f), dpi(12f))
            elevation = dp(10f)
            outlineProvider = object : ViewOutlineProvider() {
                override fun getOutline(view: View, outline: Outline) {
                    outline.setRoundRect(0, 0, view.width, view.height, radius)
                    outline.alpha = 0.18f
                }
            }
            if (Build.VERSION.SDK_INT >= 28) {
                outlineAmbientShadowColor = 0x33141414
                outlineSpotShadowColor = 0x40141414
            }
            contentDescription = "$title. $reason"
        }
        card.addView(ImageView(ctx).apply {
            setImageResource(R.drawable.ic_mark)
            contentDescription = null
        }, LinearLayout.LayoutParams(dpi(26f), dpi(26f)))

        val texts = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        val head = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val d = View(ctx).apply { background = dot(scam) }
        head.addView(d, LinearLayout.LayoutParams(dpi(7f), dpi(7f)).apply { marginEnd = dpi(7f) })
        val t = TextView(ctx).apply {
            text = title
            setTextColor(0xFF141414.toInt())
            textSize = 15f
            typeface = Typeface.create("sans-serif-medium", Typeface.BOLD)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
        }
        head.addView(t, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        texts.addView(head)
        val r = TextView(ctx).apply {
            text = reason
            setTextColor(0xFF5E5A55.toInt())
            textSize = 13f
            maxLines = 2
            ellipsize = TextUtils.TruncateAt.END
            setPadding(0, dpi(2f), 0, 0)
        }
        texts.addView(r)
        card.addView(texts, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dpi(12f) })

        card.addView(ImageView(ctx).apply {
            setImageResource(R.drawable.ic_close)
            contentDescription = try { Lang.wrap(ctx).getString(R.string.dismiss) } catch (_: Throwable) { "Dismiss" }
            scaleType = ImageView.ScaleType.CENTER
            setOnClickListener { dismiss(animated = true) }
        }, LinearLayout.LayoutParams(dpi(40f), dpi(40f)))

        // swipe up to dismiss, tap for details
        val slop = ViewConfiguration.get(ctx).scaledTouchSlop
        var downY = 0f
        var moved = false
        card.setOnTouchListener { v, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> { downY = e.rawY; moved = false; handler.removeCallbacks(hide); true }
                MotionEvent.ACTION_MOVE -> {
                    val dy = e.rawY - downY
                    if (abs(dy) > slop) moved = true
                    if (moved) {
                        v.translationY = if (dy < 0) dy else dy / 4f
                        v.alpha = (1f + dy / dp(140f)).coerceIn(0.2f, 1f)
                    }
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    val dy = e.rawY - downY
                    when {
                        moved && dy < -dp(28f) -> dismiss(animated = true)
                        !moved && e.actionMasked == MotionEvent.ACTION_UP -> {
                            val cb = onTap
                            dismiss(animated = false)
                            cb?.invoke()
                        }
                        else -> {
                            v.animate().translationY(0f).alpha(1f).setDuration(160).start()
                            handler.postDelayed(hide, AUTO_DISMISS_MS)
                        }
                    }
                    true
                }
                else -> false
            }
        }

        val frame = FrameLayout(ctx).apply {
            clipChildren = false
            clipToPadding = false
            setPadding(dpi(12f), dpi(6f), dpi(12f), dpi(16f))   // room for the soft shadow
        }
        frame.addView(card, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT))

        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            windowType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP
            y = statusBarHeight()
            windowAnimations = 0
            // No FLAG_BLUR_BEHIND: on overlay windows it blurs the whole screen, which users found jarring.
        }

        card.alpha = 0f
        card.translationY = -dp(28f)
        root = frame          // set first so a failed add is cleaned up by the caller
        wm.addView(frame, lp)
        currentKey = key
        titleView = t; reasonView = r; dotView = d
        card.animate().alpha(1f).translationY(0f).setDuration(280).setInterpolator(DecelerateInterpolator(1.6f)).start()
        handler.postDelayed(hide, AUTO_DISMISS_MS)
    }

    private fun statusBarHeight(): Int {
        val id = ctx.resources.getIdentifier("status_bar_height", "dimen", "android")
        return if (id > 0) ctx.resources.getDimensionPixelSize(id) else dpi(24f)
    }

    /** Call from the service's onDestroy: removes the banner and drops every pending show. */
    fun release() {
        released = true
        handler.removeCallbacksAndMessages(null)
        if (Looper.myLooper() == Looper.getMainLooper()) dismiss(false) else handler.post { dismiss(false) }
    }

    fun dismiss(animated: Boolean = false) {
        handler.removeCallbacks(hide)
        val v = root ?: return
        root = null; currentKey = null; titleView = null; reasonView = null; dotView = null; onTap = null
        val card = (v as? FrameLayout)?.getChildAt(0)
        if (animated && !released && card != null && v.isAttachedToWindow) {
            card.animate().cancel()
            card.animate().alpha(0f).translationY(-dp(36f)).setDuration(180)
                .setInterpolator(AccelerateInterpolator())
                .withEndAction { try { wm.removeView(v) } catch (_: Throwable) {} }
                .start()
        } else {
            card?.animate()?.cancel()
            try { wm.removeViewImmediate(v) } catch (_: Throwable) {}
        }
    }

    companion object { const val AUTO_DISMISS_MS = 6000L }
}
