/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.addCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentTransaction
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.fragment.TunnelDetailFragment
import com.wireguard.android.fragment.TunnelEditorFragment
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.AutoDeleteTunnelScheduler
import com.wireguard.android.util.DeepLinkTunnelImporter
import com.wireguard.android.util.ErrorMessages
import com.wireguard.config.BadConfigException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * CRUD interface for WireGuard tunnels. This activity serves as the main entry point to the
 * WireGuard application, and contains several fragments for listing, viewing details of, and
 * editing the configuration and interface state of WireGuard tunnels.
 */
class MainActivity : BaseActivity(), FragmentManager.OnBackStackChangedListener {
    private var actionBar: ActionBar? = null
    private var isTwoPaneLayout = false
    private var backPressedCallback: OnBackPressedCallback? = null

    // Only the name is kept: the tunnel itself is re-resolvable, and these have to survive
    // the process being killed while the VPN consent dialog is in front of us.
    private var pendingDeepLinkTunnelName: String? = null
    private var pendingDeepLinkAutoDeleteAtMillis: Long? = null

    private val permissionActivityResultLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val tunnelName = pendingDeepLinkTunnelName
        val autoDeleteAtMillis = pendingDeepLinkAutoDeleteAtMillis
        pendingDeepLinkTunnelName = null
        pendingDeepLinkAutoDeleteAtMillis = null
        if (tunnelName == null) return@registerForActivityResult
        lifecycleScope.launch {
            if (result.resultCode == RESULT_OK) {
                val tunnel = Application.getTunnelManager().getTunnels()[tunnelName]
                if (tunnel != null)
                    startDeepLinkTunnel(tunnel, tunnelName)
                else
                    showImportError(getString(R.string.deeplink_tunnel_unavailable))
            } else {
                // Say the permission was declined rather than letting the backend fail with
                // an opaque "error bringing up tunnel".
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.deeplink_vpn_permission_denied, tunnelName),
                    Toast.LENGTH_LONG
                ).show()
            }
            armAutoDelete(tunnelName, autoDeleteAtMillis)
        }
    }

    private fun handleBackPressed() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        // If the two-pane layout does not have an editor open, going back should exit the app.
        if (isTwoPaneLayout && backStackEntries <= 1) {
            finish()
            return
        }

        if (backStackEntries >= 1)
            supportFragmentManager.popBackStack()

        // Deselect the current tunnel on navigating back from the detail pane to the one-pane list.
        if (backStackEntries == 1)
            selectedTunnel = null
    }

    override fun onBackStackChanged() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        backPressedCallback?.isEnabled = backStackEntries >= 1
        if (actionBar == null) return
        // Do not show the home menu when the two-pane layout is at the detail view (see above).
        val minBackStackEntries = if (isTwoPaneLayout) 2 else 1
        actionBar!!.setDisplayHomeAsUpEnabled(backStackEntries >= minBackStackEntries)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        actionBar = supportActionBar
        isTwoPaneLayout = findViewById<View?>(R.id.master_detail_wrapper) != null
        supportFragmentManager.addOnBackStackChangedListener(this)
        backPressedCallback = onBackPressedDispatcher.addCallback(this) { handleBackPressed() }
        onBackStackChanged()
        if (savedInstanceState != null) {
            pendingDeepLinkTunnelName = savedInstanceState.getString(KEY_PENDING_DEEP_LINK_TUNNEL)
            if (savedInstanceState.containsKey(KEY_PENDING_DEEP_LINK_AUTO_DELETE))
                pendingDeepLinkAutoDeleteAtMillis = savedInstanceState.getLong(KEY_PENDING_DEEP_LINK_AUTO_DELETE)
        } else {
            handleDeepLinkIntent(intent)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        pendingDeepLinkTunnelName?.let { outState.putString(KEY_PENDING_DEEP_LINK_TUNNEL, it) }
        pendingDeepLinkAutoDeleteAtMillis?.let { outState.putLong(KEY_PENDING_DEEP_LINK_AUTO_DELETE, it) }
        super.onSaveInstanceState(outState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLinkIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        // Alarm delivery is best-effort: inexact without exact-alarm access, and dropped
        // outright by a force-stop. Sweep whatever is already past due while we are visible.
        lifecycleScope.launch {
            AutoDeleteTunnelScheduler.deleteDue(applicationContext)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_activity, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                // The back arrow in the action bar should act the same as the back button.
                onBackPressedDispatcher.onBackPressed()
                true
            }

            R.id.menu_action_edit -> {
                supportFragmentManager.commit {
                    replace(if (isTwoPaneLayout) R.id.detail_container else R.id.list_detail_container, TunnelEditorFragment())
                    setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE)
                    addToBackStack(null)
                }
                true
            }
            // This menu item is handled by the editor fragment.
            R.id.menu_action_save -> false
            R.id.menu_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSelectedTunnelChanged(
        oldTunnel: ObservableTunnel?,
        newTunnel: ObservableTunnel?
    ): Boolean {
        val fragmentManager = supportFragmentManager
        if (fragmentManager.isStateSaved) {
            return false
        }

        val backStackEntries = fragmentManager.backStackEntryCount
        if (newTunnel == null) {
            // Clear everything off the back stack (all editors and detail fragments).
            fragmentManager.popBackStackImmediate(0, FragmentManager.POP_BACK_STACK_INCLUSIVE)
            return true
        }
        if (backStackEntries == 2) {
            // Pop the editor off the back stack to reveal the detail fragment. Use the immediate
            // method to avoid the editor picking up the new tunnel while it is still visible.
            fragmentManager.popBackStackImmediate()
        } else if (backStackEntries == 0) {
            // Create and show a new detail fragment.
            fragmentManager.commit {
                add(if (isTwoPaneLayout) R.id.detail_container else R.id.list_detail_container, TunnelDetailFragment())
                setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE)
                addToBackStack(null)
            }
        }
        return true
    }

    private fun handleDeepLinkIntent(intent: Intent?) {
        if (intent == null || intent.action != Intent.ACTION_VIEW || intent.data == null) return
        // Android redelivers the original launch intent when it recreates a task whose saved
        // state has been trimmed, and hands it back when the user returns through Recents.
        // Importing again would silently resurrect a tunnel and re-activate the VPN, so treat
        // a history relaunch as nothing to do and consume the URI once it has been handled.
        if (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0) {
            intent.data = null
            return
        }
        val deepLinkIntent = Intent(intent)
        intent.data = null

        lifecycleScope.launch {
            val result = try {
                DeepLinkTunnelImporter.importFromIntent(deepLinkIntent)
            } catch (e: Throwable) {
                reportImportFailure(deepLinkIntent, e)
                return@launch
            } ?: return@launch

            val tunnel = Application.getTunnelManager().getTunnels()[result.tunnelName]
            if (tunnel == null) {
                // The import reported success, so a missing tunnel means something removed it
                // underneath us. Say so instead of finishing silently.
                showImportError(getString(R.string.deeplink_tunnel_unavailable))
                return@launch
            }
            selectedTunnel = tunnel
            if (result.shouldStart) {
                startDeepLinkTunnelWithPermission(tunnel, result.tunnelName, result.autoDeleteAtMillis)
                return@launch
            }
            val message = getString(
                when {
                    result.updatedExisting -> R.string.deeplink_import_update_success
                    else -> R.string.deeplink_import_success
                },
                result.tunnelName
            )
            Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
            armAutoDelete(result.tunnelName, result.autoDeleteAtMillis)
        }
    }

    /**
     * A [BadConfigException] carries the offending config line in its message. For a deep
     * link that line can be key material, or the body of whatever `url` pointed at — which
     * makes it a way to read a LAN endpoint into an exportable log. Keep it out of both the
     * toast and logcat.
     */
    private fun reportImportFailure(intent: Intent, e: Throwable) {
        val describedIntent = DeepLinkTunnelImporter.describeIntent(intent)
        if (e is BadConfigException) {
            Log.e(TAG, "Unable to parse config from deep link $describedIntent: ${e.javaClass.simpleName}")
            showImportError(getString(R.string.deeplink_import_invalid_config))
        } else {
            Log.e(TAG, "Unable to import tunnel from deep link: $describedIntent", e)
            showImportError(ErrorMessages[e])
        }
    }

    private fun showImportError(reason: CharSequence) {
        Toast.makeText(this, getString(R.string.import_error, reason), Toast.LENGTH_LONG).show()
    }

    /**
     * Arms the expiry only once activation has settled. Scheduling an already-due expiry
     * before that lets the delete interleave with bringing the tunnel up.
     */
    private suspend fun armAutoDelete(tunnelName: String, autoDeleteAtMillis: Long?) {
        if (autoDeleteAtMillis == null) return
        withContext(Dispatchers.IO) {
            AutoDeleteTunnelScheduler.schedule(applicationContext, tunnelName, autoDeleteAtMillis)
        }
    }

    private suspend fun startDeepLinkTunnelWithPermission(
        tunnel: ObservableTunnel,
        tunnelName: String,
        autoDeleteAtMillis: Long?
    ) {
        if (Application.getBackend() is GoBackend) {
            try {
                val intent = GoBackend.VpnService.prepare(this)
                if (intent != null) {
                    pendingDeepLinkTunnelName = tunnelName
                    pendingDeepLinkAutoDeleteAtMillis = autoDeleteAtMillis
                    permissionActivityResultLauncher.launch(intent)
                    return
                }
            } catch (e: Throwable) {
                val message = getString(R.string.error_prepare, ErrorMessages[e])
                Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                Log.e(TAG, message, e)
                armAutoDelete(tunnelName, autoDeleteAtMillis)
                return
            }
        }
        startDeepLinkTunnel(tunnel, tunnelName)
        armAutoDelete(tunnelName, autoDeleteAtMillis)
    }

    private suspend fun startDeepLinkTunnel(tunnel: ObservableTunnel, tunnelName: String) {
        try {
            Application.getTunnelManager().setTunnelState(tunnel, Tunnel.State.UP)
            Toast.makeText(this, getString(R.string.deeplink_import_and_start_success, tunnelName), Toast.LENGTH_LONG).show()
        } catch (e: Throwable) {
            val message = getString(R.string.error_up, ErrorMessages[e])
            Toast.makeText(this, message, Toast.LENGTH_LONG).show()
            Log.e(TAG, message, e)
        }
    }

    companion object {
        private const val TAG = "WG/MainActivity"
        private const val KEY_PENDING_DEEP_LINK_TUNNEL = "pending_deep_link_tunnel"
        private const val KEY_PENDING_DEEP_LINK_AUTO_DELETE = "pending_deep_link_auto_delete"
    }
}
