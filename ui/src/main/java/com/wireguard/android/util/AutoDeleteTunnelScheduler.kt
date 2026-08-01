/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import com.wireguard.android.Application
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Tracks per-tunnel expiry times for deep-link imported tunnels and arms the alarms that
 * delete them.
 *
 * Entries are keyed by tunnel name, so every path that changes or removes a tunnel name
 * has to keep this store in sync — see [rename] and [cancel]. Alarm delivery is
 * best-effort (inexact without exact-alarm access, and dropped entirely by a force-stop),
 * so [deleteDue] exists as a foreground backstop.
 */
object AutoDeleteTunnelScheduler {
    const val EXTRA_TUNNEL_NAME = "tunnel_name"

    private val requestCodeLock = Any()

    fun schedule(context: Context, tunnelName: String, expiresAtMillis: Long) {
        prefs(context).edit().putLong(expiryKey(tunnelName), expiresAtMillis).apply()
        scheduleAlarm(context, tunnelName, expiresAtMillis)
    }

    fun cancel(context: Context, tunnelName: String) {
        val requestCode = storedRequestCode(context, tunnelName)
        prefs(context).edit()
            .remove(expiryKey(tunnelName))
            .remove(requestCodeKey(tunnelName))
            .apply()
        if (requestCode != NO_REQUEST_CODE)
            alarmManager(context)?.cancel(pendingIntent(context, tunnelName, requestCode))
    }

    /**
     * Moves an expiry from [oldName] to [newName]. Without this a rename orphans the
     * alarm: it fires against a name that no longer resolves, and the expiry is silently
     * forgotten instead of being enforced.
     */
    fun rename(context: Context, oldName: String, newName: String) {
        if (oldName == newName) return
        val expiresAtMillis = prefs(context).getLong(expiryKey(oldName), NO_EXPIRY)
        cancel(context, oldName)
        if (expiresAtMillis != NO_EXPIRY)
            schedule(context, newName, expiresAtMillis)
    }

    /**
     * Re-arms every stored expiry. Alarms do not survive a reboot, an app replacement or a
     * force-stop, so this runs at every process start. Prefs and AlarmManager work happens
     * off the main thread — this is on the cold-start path for every process, including the
     * ones spun up just to deliver a broadcast.
     */
    fun rescheduleAll(context: Context) {
        val applicationContext = context.applicationContext
        applicationScope.launch(Dispatchers.IO) {
            migrateLegacyEntries(applicationContext)
            val now = System.currentTimeMillis()
            expiries(applicationContext).forEach { (tunnelName, expiresAtMillis) ->
                if (expiresAtMillis <= now)
                    deleteIfDue(applicationContext, tunnelName)
                else
                    scheduleAlarm(applicationContext, tunnelName, expiresAtMillis)
            }
        }
    }

    /**
     * Deletes every tunnel already past its expiry. Call this when the UI comes to the
     * foreground: an inexact alarm can slip well past a short TTL, and a force-stop drops
     * pending alarms outright, so the alarm alone is not a guarantee.
     */
    suspend fun deleteDue(context: Context) {
        dueTunnelNames(context).forEach { deleteIfDue(context, it) }
    }

    /**
     * Callers reach this from a broadcast receiver and from the UI, both of which run on the
     * main thread, so the prefs and AlarmManager work moves to IO here rather than at every
     * call site.
     */
    suspend fun deleteIfDue(context: Context, tunnelName: String) {
        val isDue = withContext(Dispatchers.IO) {
            val expiresAtMillis = prefs(context).getLong(expiryKey(tunnelName), NO_EXPIRY)
            if (expiresAtMillis == NO_EXPIRY || System.currentTimeMillis() < expiresAtMillis) {
                false
            } else {
                cancel(context, tunnelName)
                true
            }
        }
        if (!isDue) return
        try {
            val manager = Application.getTunnelManager()
            val tunnel = manager.getTunnels()[tunnelName] ?: return
            manager.delete(tunnel)
            Log.i(TAG, "Auto-deleted tunnel $tunnelName")
        } catch (e: Throwable) {
            Log.e(TAG, "Unable to auto-delete tunnel $tunnelName", e)
        }
    }

    private suspend fun dueTunnelNames(context: Context): List<String> = withContext(Dispatchers.IO) {
        val now = System.currentTimeMillis()
        expiries(context).filterValues { it <= now }.keys.toList()
    }

    private fun scheduleAlarm(context: Context, tunnelName: String, expiresAtMillis: Long) {
        val alarmManager = alarmManager(context) ?: return
        val pendingIntent = pendingIntent(context, tunnelName, requestCode(context, tunnelName))
        // Prefer exact delivery: an inexact allow-while-idle alarm can be batched well past
        // a short TTL while the device dozes. Exact access is revocable, so never assume it.
        if (canScheduleExactAlarms(alarmManager)) {
            try {
                alarmManager.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, expiresAtMillis, pendingIntent)
                return
            } catch (e: SecurityException) {
                Log.w(TAG, "Exact alarms unavailable, falling back to inexact for $tunnelName", e)
            }
        }
        alarmManager.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, expiresAtMillis, pendingIntent)
    }

    private fun canScheduleExactAlarms(alarmManager: AlarmManager): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return true
        return alarmManager.canScheduleExactAlarms()
    }

    /**
     * Allocates a stable request code. [String.hashCode] collides, and AlarmManager matches
     * pending intents on request code plus [Intent.filterEquals] — which ignores extras — so
     * a collision would let one tunnel's alarm silently replace another's.
     */
    private fun requestCode(context: Context, tunnelName: String): Int = synchronized(requestCodeLock) {
        val prefs = prefs(context)
        val existing = prefs.getInt(requestCodeKey(tunnelName), NO_REQUEST_CODE)
        if (existing != NO_REQUEST_CODE) return existing
        val allocated = prefs.getInt(KEY_NEXT_REQUEST_CODE, FIRST_REQUEST_CODE)
        prefs.edit()
            .putInt(requestCodeKey(tunnelName), allocated)
            .putInt(KEY_NEXT_REQUEST_CODE, allocated + 1)
            .apply()
        allocated
    }

    private fun storedRequestCode(context: Context, tunnelName: String) =
        prefs(context).getInt(requestCodeKey(tunnelName), NO_REQUEST_CODE)

    private fun expiries(context: Context): Map<String, Long> =
        prefs(context).all.mapNotNull { (key, value) ->
            if (!key.startsWith(EXPIRY_PREFIX)) return@mapNotNull null
            val expiresAtMillis = value as? Long ?: return@mapNotNull null
            key.removePrefix(EXPIRY_PREFIX) to expiresAtMillis
        }.toMap()

    /**
     * Earlier builds stored expiries under the bare tunnel name and derived the alarm
     * request code from [String.hashCode]. Move those onto the namespaced keys and drop the
     * hash-derived alarms, which the new request codes could not otherwise cancel.
     */
    private fun migrateLegacyEntries(context: Context) {
        val prefs = prefs(context)
        val legacy = prefs.all.filterKeys {
            it != KEY_NEXT_REQUEST_CODE && !it.startsWith(EXPIRY_PREFIX) && !it.startsWith(REQUEST_CODE_PREFIX)
        }
        if (legacy.isEmpty()) return
        val editor = prefs.edit()
        legacy.forEach { (tunnelName, value) ->
            editor.remove(tunnelName)
            (value as? Long)?.let { editor.putLong(expiryKey(tunnelName), it) }
            alarmManager(context)?.cancel(pendingIntent(context, tunnelName, tunnelName.hashCode()))
        }
        editor.apply()
        Log.i(TAG, "Migrated ${legacy.size} legacy auto-delete entries")
    }

    private fun pendingIntent(context: Context, tunnelName: String, requestCode: Int): PendingIntent {
        val intent = Intent(context, AutoDeleteTunnelReceiver::class.java)
            .setPackage(context.packageName)
            .putExtra(EXTRA_TUNNEL_NAME, tunnelName)
        return PendingIntent.getBroadcast(
            context,
            requestCode,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun alarmManager(context: Context): AlarmManager? = context.getSystemService(AlarmManager::class.java)

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun expiryKey(tunnelName: String) = EXPIRY_PREFIX + tunnelName

    private fun requestCodeKey(tunnelName: String) = REQUEST_CODE_PREFIX + tunnelName

    private const val PREFS_NAME = "auto_delete_tunnels"
    private const val EXPIRY_PREFIX = "expires_at:"
    private const val REQUEST_CODE_PREFIX = "request_code:"
    private const val KEY_NEXT_REQUEST_CODE = "next_request_code"
    private const val FIRST_REQUEST_CODE = 1
    private const val NO_REQUEST_CODE = 0
    private const val NO_EXPIRY = Long.MIN_VALUE
    private const val TAG = "WG/AutoDeleteTunnelScheduler"
}
