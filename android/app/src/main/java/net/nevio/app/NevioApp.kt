package net.nevio.app

import android.app.Application
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log
import net.nevio.core.mobile.Mobile
import net.nevio.core.mobile.Platform
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Starts the Go core once per process and implements its platform hooks. */
class NevioApp : Application() {
    override fun onCreate() {
        super.onCreate()
        instance = this
        val version = packageManager.getPackageInfo(packageName, 0).versionName ?: "dev"
        try {
            Mobile.start(File(filesDir, "nevio").absolutePath, platform, version)
        } catch (e: Exception) {
            Log.e(TAG, "core start failed", e)
        }
    }

    private val platform = object : Platform {
        /** Starts the VPN and returns its file descriptor; 0 without the user's consent. */
        override fun openTUN(settings: String): Long {
            if (VpnService.prepare(this@NevioApp) != null) return 0
            val service = NevioVpnService.awaitStarted(this@NevioApp)
                ?: throw IllegalStateException("VPN service did not start")
            return service.establish(JSONObject(settings)).toLong()
        }

        override fun closeTUN() {
            NevioVpnService.current?.stopVpn()
        }

        override fun keepAlive(on: Boolean) {
            main.post {
                try {
                    val i = Intent(this@NevioApp, KeepAliveService::class.java)
                    if (on) startForegroundService(i) else stopService(i)
                } catch (e: Exception) {
                    Log.w(TAG, "keep-alive service", e) // started from the background: Android refused
                }
            }
        }

        override fun apps(): String {
            val pm = packageManager
            val out = JSONArray()
            val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != packageName && hasInternet(pm, it) }
                .map { it.packageName to pm.getApplicationLabel(it).toString() }
                .sortedBy { it.second.lowercase() }
            for ((pkg, label) in apps) out.put(JSONObject().put("name", pkg).put("label", label))
            return out.toString()
        }
    }

    private fun hasInternet(pm: PackageManager, ai: ApplicationInfo): Boolean = try {
        pm.getPackageInfo(ai.packageName, PackageManager.GET_PERMISSIONS)
            .requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true
    } catch (e: Exception) {
        false
    }

    companion object {
        const val TAG = "nevio"
        lateinit var instance: NevioApp
            private set
        val main = Handler(Looper.getMainLooper())
    }
}
