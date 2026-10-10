package com.sniff.app

import android.util.Patterns
import java.util.Locale

/** Fast on-device checks. Ported from the idea behind the Sniff web app's quick rules. */
object ScamRules {

    /** [brand] = brand token a link impersonates (null if none); [badHost] = that impersonating / worst host. */
    data class Result(
        val score: Int,
        val reasons: List<String>,
        val urls: List<String>,
        val brand: String? = null,
        val badHost: String? = null
    ) {
        val topReason: String get() = reasons.firstOrNull() ?: "This message looks risky."
    }

    /** brand token -> the real site to send people to instead of the fake one */
    val officialSite: Map<String, String> = mapOf(
        "sbi" to "https://sbi.co.in", "onlinesbi" to "https://www.onlinesbi.sbi", "yono" to "https://sbi.co.in",
        "hdfc" to "https://www.hdfcbank.com", "icici" to "https://www.icicibank.com", "axis" to "https://www.axisbank.com",
        "kotak" to "https://www.kotak.com", "paytm" to "https://paytm.com", "phonepe" to "https://www.phonepe.com",
        "gpay" to "https://pay.google.com", "amazon" to "https://www.amazon.in", "flipkart" to "https://www.flipkart.com",
        "indiapost" to "https://www.indiapost.gov.in", "india-post" to "https://www.indiapost.gov.in",
        "fedex" to "https://www.fedex.com/en-in/home.html", "dhl" to "https://www.dhl.com/in-en/home.html",
        "bluedart" to "https://www.bluedart.com", "delhivery" to "https://www.delhivery.com",
        "airtel" to "https://www.airtel.in", "jio" to "https://www.jio.com", "uidai" to "https://uidai.gov.in",
        "aadhaar" to "https://uidai.gov.in", "incometax" to "https://www.incometax.gov.in", "epfo" to "https://www.epfindia.gov.in",
        "npci" to "https://www.npci.org.in", "bses" to "https://www.bsesdelhi.com", "tsspdcl" to "https://www.tssouthernpower.com",
        "parivahan" to "https://parivahan.gov.in", "echallan" to "https://echallan.parivahan.gov.in",
        "netflix" to "https://www.netflix.com", "whatsapp" to "https://www.whatsapp.com"
    )

    /** Big, well-known sites that never need an AI look when visited in a browser. */
    private val wellKnown = listOf(
        "google.com", "google.co.in", "youtube.com", "youtu.be", "wikipedia.org", "gstatic.com", "googleusercontent.com",
        "instagram.com", "facebook.com", "x.com", "twitter.com", "linkedin.com", "reddit.com", "github.com",
        "microsoft.com", "live.com", "office.com", "apple.com", "icloud.com", "yahoo.com", "bing.com", "duckduckgo.com",
        "zomato.com", "swiggy.com", "myntra.com", "irctc.co.in", "gov.in", "nic.in", "sniff-orpin.vercel.app",
        "chatgpt.com", "openai.com", "hotstar.com", "spotify.com", "telegram.org", "t.me", "wa.me"
    )

    /** True for a brand's official domain or a big well-known site: Sniff never auto-closes these. */
    fun isOfficialHost(host: String): Boolean {
        val h = host.lowercase(Locale.ROOT).removePrefix("www.")
        if (brands.values.any { isOfficial(h, it) }) return true
        return wellKnown.any { h == it || h.endsWith(".$it") }
    }

    private val suspiciousTlds = setOf(
        "xyz", "top", "click", "info", "live", "online", "site", "icu", "buzz", "rest", "shop",
        "vip", "cc", "tk", "ml", "ga", "cf", "gq", "work", "link", "loan", "win", "support",
        "cyou", "sbs", "cfd", "monster", "quest", "bond", "lol", "fun", "pw"
    )

    /** brand token -> official registrable domains */
    private val brands: Map<String, List<String>> = mapOf(
        "sbi" to listOf("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "yonosbi.com", "sbi"),
        "onlinesbi" to listOf("onlinesbi.sbi", "onlinesbi.com"),
        "yono" to listOf("yonosbi.com", "onlinesbi.sbi"),
        "hdfc" to listOf("hdfcbank.com", "hdfc.com", "hdfcbank.bank.in", "hdfclife.com", "hdfcergo.com"),
        "icici" to listOf("icicibank.com", "icici.bank.in", "iciciprulife.com", "icicilombard.com", "icicidirect.com"),
        "axis" to listOf("axisbank.com", "axis.bank.in"),
        "kotak" to listOf("kotak.com", "kotak.bank.in", "kotaksecurities.com"),
        "paytm" to listOf("paytm.com", "paytm.in", "paytmbank.com", "paytmmoney.com"),
        "phonepe" to listOf("phonepe.com"),
        "gpay" to listOf("google.com", "pay.google.com"),
        "amazon" to listOf("amazon.in", "amazon.com", "amazon.co.uk", "amazonpay.in", "amzn.to", "amzn.in", "amazon.de"),
        "flipkart" to listOf("flipkart.com", "fkrt.it", "fkrt.co"),
        "indiapost" to listOf("indiapost.gov.in", "ippbonline.com"),
        "india-post" to listOf("indiapost.gov.in"),
        "fedex" to listOf("fedex.com"),
        "dhl" to listOf("dhl.com", "dhl.co.in"),
        "bluedart" to listOf("bluedart.com"),
        "delhivery" to listOf("delhivery.com"),
        "airtel" to listOf("airtel.in", "airtel.com", "airtelxstream.in"),
        "jio" to listOf("jio.com", "jiomart.com", "jiocinema.com", "jiosaavn.com", "jiohotstar.com"),
        "uidai" to listOf("uidai.gov.in"),
        "aadhaar" to listOf("uidai.gov.in"),
        "incometax" to listOf("incometax.gov.in"),
        "epfo" to listOf("epfindia.gov.in"),
        "npci" to listOf("npci.org.in"),
        "bses" to listOf("bsesdelhi.com"),
        "tsspdcl" to listOf("tssouthernpower.com"),
        "parivahan" to listOf("parivahan.gov.in"),
        "echallan" to listOf("parivahan.gov.in"),
        "netflix" to listOf("netflix.com"),
        "whatsapp" to listOf("whatsapp.com", "wa.me", "whatsapp.net")
    )

    private val shorteners = setOf(
        "bit.ly", "tinyurl.com", "cutt.ly", "is.gd", "rb.gy", "t.ly", "shorturl.at", "tiny.cc",
        "ow.ly", "rebrand.ly", "s.id", "v.gd", "goo.su", "t.co"
    )

    private val bankContext = listOf(
        "kyc", "bank", "account", "a/c", "pan", "aadhaar", "aadhar", "upi", "netbanking", "net banking",
        "debit card", "credit card", "reward points", "yono", "sbi", "hdfc", "icici"
    )

    private val urgency = listOf(
        "urgent", "immediately", "today", "tonight", "within 24", "within 2 hours", "last chance",
        "last date", "will be blocked", "blocked", "suspended", "deactivated", "will be closed",
        "expire", "expiring", "final notice", "action required", "disconnected", "act now"
    )

    private val topics: List<Pair<String, String>> = listOf(
        "kyc" to "Asks you to update KYC, a common bank scam",
        "pan card" to "Asks about your PAN card, a common bank scam",
        "aadhaar" to "Mentions Aadhaar verification, often used in scams",
        "aadhar" to "Mentions Aadhaar verification, often used in scams",
        "electricity" to "Electricity disconnection threat, a common scam",
        "power will be disconnected" to "Electricity disconnection threat, a common scam",
        "power supply" to "Electricity disconnection threat, a common scam",
        "challan" to "Traffic challan payment link, a common scam",
        "refund" to "Promises a refund, a common way to steal money",
        "prize" to "Says you won a prize",
        "lottery" to "Says you won a lottery",
        "you have won" to "Says you won something",
        "you won" to "Says you won something",
        "congratulations" to "Unexpected congratulations, often bait",
        "reward points" to "Reward points about to expire, a common bank scam",
        "cashback" to "Promises cashback",
        "parcel" to "Parcel/delivery problem, a common courier scam",
        "customs" to "Customs fee demand, a common courier scam",
        "delivery failed" to "Failed delivery notice, a common courier scam",
        "address incomplete" to "Failed delivery notice, a common courier scam",
        "digital arrest" to "\"Digital arrest\" is always a scam",
        "part time job" to "Part-time job offer, a common task scam",
        "work from home" to "Work-from-home offer, a common task scam",
        "daily income" to "Easy daily income promise",
        "investment" to "Investment pitch",
        "double your" to "Promises to double your money",
        "account blocked" to "Says your account is blocked",
        "account will be" to "Threatens your account"
    )

    private val upiCollect = listOf(
        "collect request", "enter upi pin to receive", "enter your upi pin to receive", "upi pin to receive",
        "approve to receive", "scan to receive", "scan the qr to receive", "accept the request to receive",
        "pay to receive", "request money"
    )

    private val otpAsk = listOf("share otp", "share the otp", "tell otp", "send otp", "send the otp", "otp received", "share your otp")

    private val ipHost = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")

    fun extractUrls(text: String): List<String> {
        val out = LinkedHashSet<String>()
        val m = Patterns.WEB_URL.matcher(text)
        while (m.find()) {
            val u = m.group().trim().trimEnd('.', ',', ')', ']', '!', '?')
            // Ignore plain words that WEB_URL matches like "e.g" by requiring a dot followed by 2+ letters
            if (u.length >= 4 && u.contains('.')) out.add(u)
        }
        return out.toList()
    }

    fun hostOf(url: String): String {
        var s = url.lowercase(Locale.ROOT)
        s = s.substringAfter("://", s)
        s = s.substringBefore('/').substringBefore('?').substringBefore('#').substringBefore(':')
        s = s.substringAfter('@')
        return s.removePrefix("www.")
    }

    private fun isOfficial(host: String, domains: List<String>): Boolean =
        domains.any { d -> host == d || host.endsWith(".$d") }

    private val lureWords = listOf("kyc", "bank", "update", "verify", "reward", "login", "secure", "pay", "care", "help", "refund", "offer", "gift", "point", "pan", "account", "online", "service")

    /** Long brand names match anywhere; short ones (sbi, jio, dhl, axis...) need a word edge or a lure word nearby. */
    private fun brandHit(host: String, brand: String): Boolean {
        if (!host.contains(brand)) return false
        if (brand.length >= 5) return true
        if (Regex("(^|[^a-z])" + Regex.escape(brand)).containsMatchIn(host)) return true
        if (Regex(Regex.escape(brand) + "([^a-z]|$)").containsMatchIn(host)) return true
        return lureWords.any { host.contains(it) }
    }

    fun check(raw: String): Result {
        val text = raw.lowercase(Locale.ROOT)
        val reasons = ArrayList<String>()
        var score = 0
        val urls = extractUrls(raw)
        val hasBankContext = bankContext.any { text.contains(it) }
        var brandHitName: String? = null
        var badHost: String? = null
        var worst = 0

        for (u in urls) {
            val host = hostOf(u)
            if (host.isEmpty()) continue
            val tld = host.substringAfterLast('.')
            val lu = u.lowercase(Locale.ROOT)
            val before = score

            if (lu.substringBefore('?').endsWith(".apk") || lu.contains(".apk?") || lu.contains(".apk/")) {
                score += 50; reasons.add("Link downloads an app file (.apk). Real banks never send these.")
            }
            if (ipHost.matches(host)) {
                score += 30; reasons.add("Link uses a bare number address instead of a real website name.")
            }
            if (tld in suspiciousTlds) {
                score += 25
                if (hasBankContext) {
                    score += 20; reasons.add("Bank/KYC message with a cheap \".$tld\" website. Banks never use these.")
                } else {
                    reasons.add("Website ends in \".$tld\", which scammers use a lot.")
                }
            }
            val hostWords = host.replace('.', '-')
            for ((brand, official) in brands) {
                if (brandHit(hostWords, brand) && !isOfficial(host, official)) {
                    score += 45
                    reasons.add(0, "\"$host\" pretends to be ${brand.uppercase(Locale.ROOT)} but is not its real website.")
                    if (brandHitName == null) brandHitName = brand
                    break
                }
            }
            if (host.count { it == '-' } >= 2) { score += 10 }
            if (shorteners.any { host == it }) {
                score += 15; reasons.add("Shortened link hides where it really goes.")
            }
            if (host.startsWith("xn--") || host.contains(".xn--")) {
                score += 30; reasons.add("Website name uses look-alike letters.")
            }
            if (score - before > worst) { worst = score - before; badHost = host }
        }

        val urgent = urgency.any { text.contains(it) }
        val topic = topics.firstOrNull { text.contains(it.first) }
        if (topic != null) {
            score += 20
            reasons.add(topic.second + ".")
            if (urgent) { score += 20; reasons.add(1.coerceAtMost(reasons.size), "Pressure to act fast.") }
            if (urls.isNotEmpty()) score += 10
        } else if (urgent && urls.isNotEmpty()) {
            score += 15; reasons.add("Pressure to click a link fast.")
        }
        if (upiCollect.any { text.contains(it) }) {
            score += 45; reasons.add(0, "You never need to enter your UPI PIN or approve a request to RECEIVE money.")
        }
        if (otpAsk.any { text.contains(it) } && !text.contains("do not share") && !text.contains("don't share") && !text.contains("never share")) {
            score += 35; reasons.add(0, "Asks for your OTP. Never share an OTP.")
        }
        return Result(score.coerceIn(0, 100), reasons.distinct(), urls, brandHitName, badHost)
    }
}
