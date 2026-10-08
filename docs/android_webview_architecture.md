# TessAi Mobile Architecture: Web Framework & Android WebView Roadmap

## 1. Executive Summary & Separation of Concerns

TessAi is hosted directly on an Android smartphone via **Termux and Node.js**. Because it operates within mobile hardware constraints (battery life, thermal throttling, limited RAM, and storage), the architecture strictly enforces two separate, non-overlapping web capabilities:

```
TessAi System Architecture
│
├── 1. Web Framework (AI Subsystem)
│      ├── DuckDuckGo HTML & API Search Provider
│      ├── Multi-layered SSRF & Private IP Protection
│      ├── Clean HTML Extraction (~12k chars max context)
│      └── Context Grounding with Verifiable Citations
│
├── 2. User Web Browser (Interactive Feature)
│      ├── Direct Client-Engine Rendering (0 Node.js Overhead)
│      ├── Navigation Controls (Back, Forward, Reload, Home)
│      ├── URL Address Bar & Lock Indicator
│      ├── Instant Memory Release (Unload to about:blank)
│      └── Optional "Ask TessAi" Analysis Hook
│
└── 3. Future Android App Packaging (WebView Roadmap)
       ├── Uses System Android WebView (Chromium) Already on Device
       ├── Zero Bundled Chromium Binaries (0 MB Disk Bloat)
       ├── TessAiNative JavaScript Interface Bridge
       └── Native Android Lifecycle & Memory Management
```

---

## 2. Web Framework (AI Search Subsystem)

- **Owner**: AI Chatbot (`server.js` + `web_access.js`).
- **Purpose**: Gives the AI model live internet knowledge, factual grounding, and source citation without human manual interaction.
- **Workflow**:
  1. User asks a question (e.g., *"What happened in the latest SpaceX launch?"*).
  2. AI pipeline checks rate limits (30 reqs/min per user) and analyzes intent.
  3. Safe DNS pre-lookup ensures target addresses are strictly public (SSRF immunity).
  4. DuckDuckGo retrieves organic search results; the top source webpage is safely fetched and stripped of scripts, styles, and tags.
  5. The extracted factual summary is provided as grounded context to Groq / OpenRouter.
- **Independence**: The Web Framework never interacts with or controls the user's Web Browser viewport.

---

## 3. Web Browser (User Interactive Feature)

- **Owner**: The User.
- **Purpose**: A personal, lightweight browser allowing the user to view web pages, follow links, fill forms, and browse freely.
- **Termux / Web Implementation Constraints**:
  - **No Fake Proxy**: The previous HTML-rewriting proxy (`/api/browser/proxy`) has been removed. Rewriting DOM and stripping headers wastes mobile CPU, consumes RAM in Termux, and breaks modern JavaScript applications.
  - **Direct Client Rendering**: The browser viewport loads URLs directly using the client's rendering engine.
  - **Respect for Origin Policies**: If a site enforces `X-Frame-Options: SAMEORIGIN` or CSP `frame-ancestors` (e.g., Google, ChatGPT), standard browser security will restrict embedded framing. An informative status banner informs the user, and a single tap on **"Open in Device Browser"** launches it directly.
  - **Memory Reclamation**: Mobile browsers must conserve RAM. Clicking **Home** or choosing **"Free Memory / Clear View"** immediately sets the viewport to `about:blank`, releasing browser memory buffers.
- **Optional "Ask TessAi" Hook**:
  - Located under the browser menu (`⋮`).
  - When explicitly clicked by the user, it switches to Chat and pre-populates the prompt: `Can you analyze and summarize this webpage: <url>`.
  - The AI never observes, tracks, or records normal user browser activity.

---

## 4. Why Bundling Chromium in Termux is Strictly Avoided

| Approach | Storage Footprint | RAM Footprint | Battery & CPU Impact | Termux Compatibility |
| :--- | :--- | :--- | :--- | :--- |
| **Bundling Puppeteer / Headless Chromium** | **~350 MB – 500 MB+** | **400 MB+ per process** | **Severe drain & thermal throttling** | **Fails frequently** (glibc / PRoot / shared library conflicts on ARM64) |
| **Fake HTML Proxy in Node.js** | ~0 MB | ~50 MB – 100 MB buffers | High CPU parsing large HTML | Degraded fidelity; breaks complex JS sites |
| **Direct Client Rendering (Current)** | **0 MB** | **0 MB in Node.js** | **Minimal** (delegated to client browser) | **100% Native & Stable** |
| **Future Android System WebView** | **0 MB** (Already installed) | Handled by OS | Highly optimized hardware acceleration | **100% Native Android** |

---

## 5. Future Android App Packaging (WebView Architecture)

When TessAi is compiled into an Android APK, it will leverage the **Android System WebView** already installed on the user's phone, avoiding any bundled browser engines.

### 5.1 Architecture Diagram

```
┌────────────────────────────────────────────────────────┐
│               Android Application (APK)                │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │                MainActivity.kt                   │  │
│  │                                                  │  │
│  │  ┌─────────────────────┐  ┌────────────────────┐ │  │
│  │  │   TessAi Web UI     │  │   Native Browser   │ │  │
│  │  │   (Localhost:8000)  │  │   WebView View     │ │  │
│  │  │   - AI Chat (WF)    │  │   - Top-level user │ │  │
│  │  │   - Files Viewer    │  │     agent rendering│ │  │
│  │  └──────────┬──────────┘  └──────────▲─────────┘ │  │
│  │             │                        │           │  │
│  │             │  TessAiNativeBridge    │           │  │
│  │             └────────────────────────┘           │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │    Embedded Node.js / Termux Background Worker   │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

### 5.2 Native JavaScript Interface Specification

Inside the frontend (`public/premium.html`), navigation checks for the native bridge:

```javascript
if (window.TessAiNative && typeof window.TessAiNative.openUrl === 'function') {
  window.TessAiNative.openUrl(url);
  return;
}
```

In the Android native shell (`MainActivity.kt`):

```kotlin
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var appWebView: WebView
    private lateinit var browserWebView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        appWebView = findViewById(R.id.appWebView)
        browserWebView = findViewById(R.id.browserWebView)

        // Setup TessAi UI
        appWebView.settings.javaScriptEnabled = true
        appWebView.settings.domStorageEnabled = true
        appWebView.addJavascriptInterface(TessAiNativeBridge(this), "TessAiNative")
        appWebView.loadUrl("http://127.0.0.1:8000/premium.html")

        // Setup Interactive Browser using Device System WebView
        browserWebView.settings.javaScriptEnabled = true
        browserWebView.settings.domStorageEnabled = true
        browserWebView.settings.setSupportMultipleWindows(false)
        browserWebView.webViewClient = WebViewClient()
    }

    inner class TessAiNativeBridge(val activity: MainActivity) {
        @JavascriptInterface
        fun openUrl(url: String) {
            activity.runOnUiThread {
                activity.browserWebView.loadUrl(url)
            }
        }

        @JavascriptInterface
        fun destroyBrowser() {
            activity.runOnUiThread {
                activity.browserWebView.loadUrl("about:blank")
                activity.browserWebView.clearCache(true)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        browserWebView.destroy()
        appWebView.destroy()
    }
}
```

### 5.3 Memory Lifecycle Rules for Android
1. **Single Instance**: Maintain exactly one `browserWebView` instance.
2. **On Background / Navigation Away**: Call `browserWebView.onPause()` to pause timers and animation frames.
3. **On Low Memory Notification (`onTrimMemory`)**: Execute `browserWebView.clearCache(false)` and release offscreen drawing buffers.
4. **On App Termination (`onDestroy`)**: Explicitly remove from parent ViewGroup and invoke `destroy()`.
