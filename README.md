# Sniff for Android

Sniff sits quietly in the background and warns you when a scam link or message shows up on your screen: fake KYC/bank updates, look-alike bank and shopping websites, parcel/customs fee, electricity disconnection, traffic challan, prize/refund bait, `.apk` download links and UPI "collect request" tricks.

Like AI assistants that can "see your screen", Sniff uses Android's **Accessibility** setting to read the text that is visible on screen. When something looks like a scam you get a **"Don't click this link"** alert and a small red banner at the top of the screen for a few seconds. Safe content stays silent.

Web version: https://sniff-orpin.vercel.app

## Install (side-load)

1. Open the latest release: https://github.com/DarkPlayz98/sniff-android/releases/latest and download `sniff-v*.apk`.
2. Open the downloaded file. If Android asks, allow your browser/Files app to **install unknown apps**.
3. Open **Sniff** and allow notifications (Android 13+).
4. Tap **Turn on screen protection** → in Accessibility settings tap **Sniff scam warnings** (may be under "Installed apps"/"Downloaded apps") → switch it on.
5. The status line in Sniff now says **On**. You can also paste any message into **Check a message**.

## Privacy

- Sniff reads only visible **text** (never screenshots). It never reads password fields and ignores banking/UPI apps (SBI YONO, HDFC, ICICI, Axis, Kotak, PhonePe, Paytm, Google Pay, BHIM and more), password managers and keyboards.
- Nothing is stored on the phone or on a server. A 10-minute "already checked" memory lives in RAM only so the same link isn't checked twice.
- Most checks run on the phone. Only when a message looks risky or contains a new link is that piece of text sent to Sniff's checker (`POST https://sniff-orpin.vercel.app/api/sniff`, at most one request every 8 seconds). It isn't saved.

## How it works

- `SniffAccessibilityService` listens for window/content/text changes (800 ms event timeout + 700 ms debounce), walks the active window's view tree, collects visible text and links (`Patterns.WEB_URL`).
- `ScamRules` scores it on-device: suspicious TLDs (.xyz .top .click .info …) especially with bank/KYC wording, look-alike brand domains (sbi, hdfc, icici, paytm, phonepe, amazon, flipkart, india post, fedex, airtel, jio …), `.apk` links, IP-address links, shorteners, urgency + KYC/blocked/electricity/challan/refund/prize words, UPI collect wording, OTP requests.
- If the local score is high or a new link appears, it asks the live checker. SCAM/SUSPICIOUS → heads-up notification + 6-second overlay banner (`TYPE_ACCESSIBILITY_OVERLAY`, no extra permission). If the checker is unreachable, a high local score still warns.

## Build

GitHub Actions (`.github/workflows/build.yml`) builds an **unsigned** release APK (published as a temporary `unsigned-vX.Y.Z` prerelease). The maintainer downloads it, signs it offline with the private release key, and commits the signed file to `dist/sniff-vX.Y.Z.apk`; a push to `main` containing that file publishes it as the GitHub Release `vX.Y.Z` (asset `sniff-vX.Y.Z.apk`).

Locally: JDK 17 + Android SDK 35, then `gradle assembleRelease` (Gradle 8.9, AGP 8.7.3, Kotlin 2.0.21). No third-party libraries. Without a local keystore this produces `app-release-unsigned.apk`.

### Signing

Releases are signed locally by the maintainer with `apksigner` (APK Signature Scheme v2 + v3). **The private key and its password are never stored in this repository or in CI.**

Release signing certificate SHA-256 (from v0.5.0):
`C6:D8:6E:CC:4F:23:38:75:9F:D7:60:8E:FC:9C:4C:46:91:63:91:2A:C4:81:D2:95:0F:86:86:A0:C2:9C:B8:84`

> **v0.5.0 uses a new signing key:** uninstall the old Sniff once, then install v0.5.0. (Versions up to v0.4.0 were signed with a test key that has been retired.)

## Google Play note

Google Play restricts use of the AccessibilityService API. Apps that use it must submit the Accessibility API declaration in Play Console, show a prominent in-app disclosure and get consent, and explain why the use is essential; non-accessibility-tool uses are reviewed case by case and may be rejected. Until that's done, Sniff is distributed as a side-loaded APK from GitHub Releases.

## Limits

- Reads text only; scam content inside images/videos isn't seen.
- Some apps (and secure/banking screens) hide their content from accessibility services.
- Rules are tuned for Indian scams; the live checker handles the rest.
