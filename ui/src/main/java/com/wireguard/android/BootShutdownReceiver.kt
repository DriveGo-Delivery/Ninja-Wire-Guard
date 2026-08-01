/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.wireguard.android.backend.WgQuickBackend
import com.wireguard.android.util.AutoDeleteTunnelScheduler
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch

class BootShutdownReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        // Alarms are cleared by a reboot, and this has to run regardless of backend: the
        // WgQuickBackend check below returns early on every non-rooted device, which is
        // where the vast majority of installs live.
        if (Intent.ACTION_BOOT_COMPLETED == action)
            AutoDeleteTunnelScheduler.rescheduleAll(context)
        applicationScope.launch {
            if (Application.getBackend() !is WgQuickBackend) return@launch
            val tunnelManager = Application.getTunnelManager()
            if (Intent.ACTION_BOOT_COMPLETED == action) {
                Log.i(TAG, "Broadcast receiver restoring state (boot)")
                tunnelManager.restoreState(false)
            } else if (Intent.ACTION_SHUTDOWN == action) {
                Log.i(TAG, "Broadcast receiver saving state (shutdown)")
                tunnelManager.saveState()
            }
        }
    }

    companion object {
        private const val TAG = "WireGuard/BootShutdownReceiver"
    }
}
