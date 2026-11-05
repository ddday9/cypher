package net.nevio.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.util.Log
import net.nevio.core.mobile.Mobile
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * The system VPN. It only creates the TUN: cypher (Go) reads and writes its
 * packets. nevio's own sockets bypass the VPN because the app itself is
 * never part of it. No foreground notification is shown; the system's key
 * icon in the status bar is visible to the user only, not to other apps.
 */
class NevioVpnService : VpnService() {

    override fun onCreate() {
        super.onCreate()
        current = this
        started?.countDown()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Started by the system for "Always-on VPN": connect with the saved settings.
        if (intent?.action == SERVICE_INTERFACE) {
            thread(name = "nevio-always-on") {
                val err = Mobile.connect()
                if (err.isNotEmpty()) Log.w(NevioApp.TAG, "always-on connect: $err")
            }
        }
        return START_NOT_STICKY
    }

    /** Builds the VPN; returns a detached file descriptor owned by Go from now on. */
    fun establish(s: JSONObject): Int {
        val b = Builder()
            .setSession(getString(R.string.vpn_session))
            .setMtu(s.optInt("mtu", 1500))
        val (a4, p4) = s.getString("address4").split("/")
        b.addAddress(a4, p4.toInt())
        b.addRoute("0.0.0.0", 0)
        b.addDnsServer(s.getString("dns"))
        s.optString("address6").takeIf { it.isNotEmpty() }?.let {
            val (a6, p6) = it.split("/")
            try {
                b.addAddress(a6, p6.toInt())
                b.addRoute("::", 0)
            } catch (e: Exception) {
                Log.w(NevioApp.TAG, "IPv6 not added", e)
            }
        }
        val allowed = s.optJSONArray("allowed")
        if (allowed != null && allowed.length() > 0) {
            // Only these apps use the VPN; for every other app there is no VPN.
            var any = false
            for (i in 0 until allowed.length()) any = addApp(allowed.getString(i), true, b) || any
            if (!any) throw IllegalStateException("none of the selected apps is installed")
        } else {
            b.addDisallowedApplication(packageName) // our own connections go straight out
            val disallowed = s.optJSONArray("disallowed")
            if (disallowed != null) for (i in 0 until disallowed.length()) addApp(disallowed.getString(i), false, b)
        }
        if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
        val pfd = b.establish() ?: throw IllegalStateException("VPN permission was revoked")
        return pfd.detachFd()
    }

    private fun addApp(pkg: String, allow: Boolean, b: Builder): Boolean = try {
        if (allow) b.addAllowedApplication(pkg) else b.addDisallowedApplication(pkg)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false // not installed
    }

    fun stopVpn() {
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user turned it off in the system settings.
        thread(name = "nevio-revoke") { Mobile.disconnect() }
        super.onRevoke()
    }

    override fun onDestroy() {
        if (current === this) current = null
        super.onDestroy()
    }

    companion object {
        @Volatile var current: NevioVpnService? = null
        @Volatile private var started: CountDownLatch? = null

        /** Starts the service (if needed) and waits for it. */
        fun awaitStarted(ctx: Context): NevioVpnService? {
            current?.let { return it }
            val latch = CountDownLatch(1)
            started = latch
            ctx.startService(Intent(ctx, NevioVpnService::class.java))
            latch.await(5, TimeUnit.SECONDS)
            return current
        }
    }
}
