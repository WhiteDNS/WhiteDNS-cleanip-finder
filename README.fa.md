<div dir="rtl">

# وایت‌دی‌ان‌اس کلین آی‌پی فایندر

<p align="center">
  <img src="android/app/src/main/res/drawable-nodpi/whitedns_logo.png" alt="WhiteDNS IP Scanner" width="150">
</p>

<p align="center">
  <strong>نسخه دسکتاپ ۱.۲ و اندروید ۱.۲ برای پیدا کردن آی‌پی تمیز، اسکن پراکسی، خروجی ASN و ابزارهای WhiteDNS.</strong>
</p>

<p align="center">
  <a href="README.md"><strong>English</strong></a>
  ·
  <a href="README.fa.md"><strong>فارسی</strong></a>
  ·
  <a href="https://github.com/tajirax/WhiteDNS-cleanip-finder/releases"><strong>دانلودها</strong></a>
</p>

---

## آخرین نسخه‌ها

| نسخه | پلتفرم | شامل چه چیزهایی است | مناسب برای |
|---|---|---|---|
| **WhiteDNS Desktop 1.2** | ویندوز، لینوکس، مک، ترموکس | محیط ترمینالی، ابزارهای پراکسی، موتور اسکن، ابزار کانفیگ، خروجی‌های چندسکویی | کاربران حرفه‌ای، اسکن دسکتاپ، کارهای حجیم |
| **WhiteDNS IP Scanner Android 1.2** | اندروید API 21 به بالا | اپ اندروید، اسکن IP/CIDR، اسکن SNI، اسکن HTTP/SOCKS5، خروجی ASN، APK/AAB امضاشده | اسکن با موبایل و پیدا کردن آی‌پی تمیز در حالت قابل حمل |

دانلود آخرین فایل‌ها از صفحه **GitHub Releases**:

```text
https://github.com/tajirax/WhiteDNS-cleanip-finder/releases
```

---

## WhiteDNS چه کاری انجام می‌دهد؟

WhiteDNS یک ابزار برای پیدا کردن آی‌پی تمیز و مدیریت جریان‌های پراکسی است. این برنامه رنج‌های IP را باز می‌کند، پورت‌ها را تست می‌کند، رفتار TLS/SNI را بررسی می‌کند، پراکسی‌های HTTP و SOCKS5 را اعتبارسنجی می‌کند، هدف‌های ASN را خروجی می‌گیرد و نتیجه‌ها را برای استفاده بعدی ذخیره می‌کند.

### امکانات اصلی

- موتور اسکن بومی Go با پشتیبانی از CIDR، کنترل همزمانی، pause/resume، stop، پیشرفت و خروجی نتیجه‌ها.
- نسخه دسکتاپ با محیط TUI برای اسکن، routing، workflowهای DPI/desync، ابزار کانفیگ و پراکسی.
- اپ اندروید با اسکن IP/CIDR، اسکن SNI، اسکن HTTP Proxy، اسکن SOCKS5، خروجی ASN و سرویس foreground.
- پشتیبانی از ASN با دیتاست‌های embedded.
- خروجی‌های دسکتاپ به صورت فایل‌های standalone.
- خروجی اندروید برای ABIهای `armeabi-v7a`، `arm64-v8a`، `x86`، `x86_64`، نسخه universal APK و AAB.

---

## راهنمای نسخه دسکتاپ ۱.۲

### دانلود

از بخش **Releases** فایل مناسب سیستم‌عامل خود را دانلود کنید:

| سیستم‌عامل | فایل |
|---|---|
| ویندوز | `whitedns-windows-amd64.exe` |
| لینوکس x64 | `whitedns-linux-amd64` |
| لینوکس ARM64 | `whitedns-linux-arm64` |
| مک Intel | `whitedns-macos-amd64` |
| مک Apple Silicon | `whitedns-macos-arm64` |
| ترموکس / اندروید ARM64 | `whitedns-termux-arm64` |

### اجرا

در ویندوز PowerShell:

```powershell
.\whitedns-windows-amd64.exe -mode ui -host 0.0.0.0 -port 8080
```

در لینوکس یا مک:

```bash
chmod +x ./whitedns-linux-amd64
./whitedns-linux-amd64 -mode ui -host 0.0.0.0 -port 8080
```

حالت فقط پراکسی:

```bash
./whitedns-linux-amd64 -mode proxy -host 0.0.0.0 -port 8080
```

### نکته‌های دسکتاپ

- نتیجه‌ها و لاگ‌ها کنار فایل اجرایی در پوشه‌های خروجی WhiteDNS ذخیره می‌شوند.
- دیتاست‌های ASN و assetهای مورد نیاز داخل فایل اجرایی embedded هستند.
- برای تجربه کامل از محیط TUI استفاده کنید.
- اگر فقط رفتار پراکسی یا تونل محلی را می‌خواهید، حالت proxy کافی است.

---

## راهنمای اندروید ۱.۲

### دانلود

از بخش **Releases** یکی از فایل‌های اندروید را دانلود کنید:

| فایل | کاربرد |
|---|---|
| `WhiteDNS-IP-Scanner-universal-release.apk` | پیشنهاد شده برای بیشتر کاربران |
| `WhiteDNS-IP-Scanner-arm64-v8a-release.apk` | بیشتر گوشی‌های اندرویدی جدید |
| `WhiteDNS-IP-Scanner-armeabi-v7a-release.apk` | دستگاه‌های قدیمی‌تر ۳۲ بیتی ARM |
| `WhiteDNS-IP-Scanner-x86-release.apk` / `x86_64` | امولاتور یا دستگاه‌های x86 |
| `WhiteDNS-IP-Scanner-release.aab` | آپلود در Play Store |

### نصب

۱. فایل APK را روی گوشی دانلود کنید.  
۲. آن را با فایل‌منیجر باز کنید.  
۳. اگر اندروید درخواست کرد، اجازه نصب از مرورگر یا فایل‌منیجر را فعال کنید.  
۴. برنامه **WhiteDNS IP Scanner** را باز کنید.  
۵. برای ساخت و نوشتن در پوشه عمومی `WhiteDNS Scanner`، دسترسی folder/storage را بدهید.

### امکانات اندروید

- اسکن IP / CIDR
- اسکن SNI
- اسکن HTTP Proxy
- اسکن SOCKS5
- خروجی ASN
- Pause / Resume / Stop
- ذخیره نتیجه‌ها، لاگ‌ها و خروجی ASN در پوشه `WhiteDNS Scanner`

### مسیر خروجی در اندروید

اگر دسترسی پوشه داده شود، خروجی در این مسیر ذخیره می‌شود:

```text
/sdcard/WhiteDNS Scanner/
```

مسیر جایگزین داخل پوشه اختصاصی اپ:

```text
/sdcard/Android/data/com.whitescan.app/files/WhiteDNS Scanner/
```

---

## ساخت از سورس

### نیازمندی‌ها

- Go نسخه 1.25 یا بالاتر
- PowerShell در ویندوز یا bash در لینوکس/مک
- برای اندروید: JDK 17، Android SDK API 34، NDK r26، Gradle 8.7 و gomobile

### ساخت دسکتاپ

ساخت همه خروجی‌های دسکتاپ:

```powershell
.\build_cross_platform.ps1 -CleanBuild
```

اجرای تست‌ها:

```powershell
go test ./...
```

### ساخت اندروید

ساخت AAR مربوط به موتور Go:

```powershell
.\build-aar.ps1
```

ساخت اپ اندروید از پوشه `android`:

```powershell
cd android
gradle assembleRelease bundleRelease
```

راهنمای کامل‌تر ساخت اندروید:

```text
android/README.md
```

---

## ساختار پروژه

| مسیر | کاربرد |
|---|---|
| `cmd/whitedns` | ورودی برنامه دسکتاپ |
| `internal/ui` | محیط ترمینالی و صفحه‌های workflow |
| `internal/scanner` | موتور اسکن، probeها، pause/resume و اسکن پراکسی |
| `internal/asn` | بارگذاری و جستجوی ASN |
| `internal/bundledata` | دیتاست‌ها و assetهای embedded |
| `internal/proxy` | اجزای سرور پراکسی |
| `mobile` | bridge مربوط به Go mobile برای اندروید |
| `android` | اپ اندروید |

---

## مشارکت

۱. یک branch بسازید.  
۲. دستور `go test ./...` را اجرا کنید.  
۳. target مربوط به تغییرات را build کنید.  
۴. Pull Request را با توضیح واضح و نتیجه تست‌ها ارسال کنید.

---

## هشدار

از WhiteDNS فقط روی شبکه‌ها، هاست‌ها و رنج‌هایی استفاده کنید که مالک آن‌ها هستید یا اجازه تست دارید. مسئولیت رعایت قوانین محلی، قوانین سرویس‌دهنده و سیاست‌های شبکه با شماست.

</div>
