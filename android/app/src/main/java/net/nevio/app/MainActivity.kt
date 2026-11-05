package net.nevio.app

import android.annotation.SuppressLint
import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import net.nevio.core.mobile.Mobile
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors

/**
 * The interface is the same web UI as nevio on Windows, served from the Go
 * core inside the app. It talks to the core through a JavaScript bridge, so
 * nevio has no local HTTP server and no open port that other apps could find.
 */
class MainActivity : Activity() {
    private lateinit var web: WebView
    private val pool = Executors.newCachedThreadPool()
    private var pendingConnect: Pair<Int, String>? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        web = WebView(this)
        setContentView(web)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.setBackgroundColor(0xFF0F1218.toInt())
        web.addJavascriptInterface(Bridge(), "NevioAndroid")
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse {
                val url = req.url
                if (url.host != HOST) return empty(403) // the page never talks to the network itself
                val path = url.path?.trimStart('/').orEmpty().ifEmpty { "index.html" }
                val data = Mobile.asset(path) ?: return empty(404)
                return WebResourceResponse(mime(path), "utf-8", ByteArrayInputStream(data)).apply {
                    responseHeaders = mapOf("Cache-Control" to "no-store")
                }
            }

            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
                if (req.url.host == HOST) return false
                // tg://socks?… and other links open in their apps.
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, req.url))
                } catch (e: Exception) {
                    toastJs("Нет приложения для этой ссылки")
                }
                return true
            }
        }
        web.loadUrl("https://$HOST/index.html")
    }

    private fun empty(code: Int) =
        WebResourceResponse("text/plain", "utf-8", code, "x", emptyMap(), ByteArrayInputStream(ByteArray(0)))

    private fun mime(path: String) = when (path.substringAfterLast('.')) {
        "html" -> "text/html"
        "js" -> "application/javascript"
        "css" -> "text/css"
        "png" -> "image/png"
        "svg" -> "image/svg+xml"
        else -> "application/octet-stream"
    }

    private fun reply(id: Int, json: String) {
        runOnUiThread { web.evaluateJavascript("window.__nevioReply($id, ${JSONObject.quote(json)})", null) }
    }

    private fun toastJs(msg: String) {
        runOnUiThread { web.evaluateJavascript("toast(${JSONObject.quote(msg)}, true)", null) }
    }

    private fun errorEnvelope(msg: String) =
        JSONObject().put("status", 400).put("body", JSONObject().put("error", msg)).toString()

    /** VPN mode needs the user's consent once (the system dialog). */
    private fun needsVpnConsent(): Boolean {
        val state = JSONObject(Mobile.call("GET", "/api/state", "")).optJSONObject("body")
        val mode = state?.optJSONObject("data")?.optJSONObject("settings")?.optString("mode")
        return mode == "tun" && VpnService.prepare(this) != null
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_REQUEST) return
        val (id, body) = pendingConnect ?: return
        pendingConnect = null
        if (resultCode != RESULT_OK) {
            reply(id, errorEnvelope("Без разрешения Android на VPN режим «VPN» не работает. Можно выбрать «Прокси (без VPN)»."))
            return
        }
        pool.execute { reply(id, Mobile.call("POST", "/api/connect", body)) }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        moveTaskToBack(true) // keep running, like closing the window on Windows
    }

    inner class Bridge {
        @JavascriptInterface
        fun call(id: Int, method: String, path: String, body: String) {
            pool.execute {
                if (method == "POST" && path == "/api/connect" && needsVpnConsent()) {
                    runOnUiThread {
                        pendingConnect = id to body
                        startActivityForResult(VpnService.prepare(this@MainActivity), VPN_REQUEST)
                    }
                    return@execute
                }
                reply(id, Mobile.call(method, path, body))
            }
        }

        @JavascriptInterface
        fun copy(text: String) {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("nevio", text))
        }

        @JavascriptInterface
        fun paste(): String {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this@MainActivity)?.toString().orEmpty()
        }

        /** Which launcher entry is enabled: "default", "notes" or "calc". */
        @JavascriptInterface
        fun icon(): String = ALIASES.entries.firstOrNull { (_, cls) ->
            packageManager.getComponentEnabledSetting(ComponentName(this@MainActivity, cls)).let {
                it == PackageManager.COMPONENT_ENABLED_STATE_ENABLED ||
                    (it == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT && cls.endsWith("LauncherDefault"))
            }
        }?.key ?: "default"

        @JavascriptInterface
        fun setIcon(name: String) {
            if (name !in ALIASES) return
            for ((key, cls) in ALIASES) {
                val state = if (key == name) PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                else PackageManager.COMPONENT_ENABLED_STATE_DISABLED
                packageManager.setComponentEnabledSetting(ComponentName(this@MainActivity, cls), state,
                    PackageManager.DONT_KILL_APP)
            }
        }

        @JavascriptInterface
        fun openUrl(url: String) {
            runOnUiThread {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                } catch (e: Exception) {
                    toastJs("Нет приложения для этой ссылки")
                }
            }
        }
    }

    companion object {
        const val HOST = "nevio.invalid"
        const val VPN_REQUEST = 1
        val ALIASES = mapOf(
            "default" to "net.nevio.app.LauncherDefault",
            "notes" to "net.nevio.app.LauncherNotes",
            "calc" to "net.nevio.app.LauncherCalc",
        )
    }
}
