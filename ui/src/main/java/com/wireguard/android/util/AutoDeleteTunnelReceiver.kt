/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.launch

class AutoDeleteTunnelReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val tunnelName = intent.getStringExtra(AutoDeleteTunnelScheduler.EXTRA_TUNNEL_NAME) ?: return
        val applicationContext = context.applicationContext
        // Deleting a tunnel has to bring the backend down and touch the config store, none
        // of which fits in onReceive. Hold the broadcast open so the process is not killed
        // partway through the teardown.
        val pendingResult = goAsync()
        applicationScope.launch {
            try {
                AutoDeleteTunnelScheduler.deleteIfDue(applicationContext, tunnelName)
            } finally {
                pendingResult.finish()
            }
        }
    }
}
