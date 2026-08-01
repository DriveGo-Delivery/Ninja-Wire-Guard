/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Intent
import android.net.Uri
import android.util.Base64
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

object DeepLinkTunnelImporter {
    data class Result(
        val tunnelName: String,
        val updatedExisting: Boolean,
        val shouldStart: Boolean,
        val autoDeleteAtMillis: Long?
    )

    /**
     * Imports or updates the tunnel described by [intent] and returns what the caller still
     * has to do with it.
     *
     * Arming the expiry alarm is deliberately *not* done here. An expiry that is already due
     * fires as soon as it is scheduled, and doing that before the tunnel finishes coming up
     * lets the delete interleave with activation — leaving the backend running a tunnel the
     * manager no longer tracks and the UI cannot switch off. The caller schedules it once
     * activation has settled; see [Result.autoDeleteAtMillis].
     */
    suspend fun importFromIntent(intent: Intent): Result? {
        if (intent.action != Intent.ACTION_VIEW) return null
        val uri = intent.data ?: return null
        if (uri.scheme !in SUPPORTED_SCHEMES) return null

        val configText = resolveConfigText(uri)
            ?: throw IllegalArgumentException("Missing conf, config, conf_b64, config_b64, url, or fragment")
        Log.i(TAG, "Resolved deep link config text from ${describeUri(uri)}")
        val now = System.currentTimeMillis()
        val metadata = DeepLinkPolicy.parseMetadata(configText, now)
        val configForParser = DeepLinkPolicy.stripNonConfigLines(configText)
        val config = withContext(Dispatchers.Default) {
            Config.parse(ByteArrayInputStream(configForParser.toByteArray(StandardCharsets.UTF_8)))
        }
        val name = resolveName(uri)
        val shouldStart = DeepLinkPolicy.parseBoolean(uri.getQueryParameter("up"))
            ?: DeepLinkPolicy.parseBoolean(uri.getQueryParameter("start"))
            ?: DeepLinkPolicy.parseBoolean(uri.getQueryParameter("activate"))
            ?: metadata.activate
            ?: true
        val autoDeleteAtMillis = resolveAutoDeleteAtMillis(uri, metadata, now)
        val manager = Application.getTunnelManager()
        val tunnels = manager.getTunnels()
        val existing = tunnels[name]
        val tunnel = if (existing != null) {
            manager.setTunnelConfig(existing, config)
            Log.i(TAG, "Updated tunnel $name from deep link")
            existing
        } else {
            manager.create(name, config).also { Log.i(TAG, "Created tunnel $name from deep link") }
        }
        // Clearing a stale expiry is safe to do now — unlike arming one, it cannot delete
        // anything. Scheduling is left to the caller.
        if (autoDeleteAtMillis == null)
            withContext(Dispatchers.IO) {
                AutoDeleteTunnelScheduler.cancel(Application.get().applicationContext, tunnel.name)
            }
        Log.i(TAG, "Deep link import complete for ${tunnel.name}, shouldStart=$shouldStart, autoDeleteAtMillis=$autoDeleteAtMillis")
        return Result(tunnel.name, existing != null, shouldStart, autoDeleteAtMillis)
    }

    fun describeIntent(intent: Intent) = intent.data?.let(::describeUri) ?: "<no data>"

    private suspend fun resolveConfigText(uri: Uri): String? {
        uri.getQueryParameter("conf")?.takeIf { it.isNotBlank() }?.let { return it }
        uri.getQueryParameter("config")?.takeIf { it.isNotBlank() }?.let { return it }
        uri.getQueryParameter("conf_b64")?.takeIf { it.isNotBlank() }?.let { return decodeBase64(it) }
        uri.getQueryParameter("config_b64")?.takeIf { it.isNotBlank() }?.let { return decodeBase64(it) }
        uri.getQueryParameter("url")?.takeIf { it.isNotBlank() }?.let { return downloadConfig(it) }
        return uri.fragment?.takeIf { it.contains("[Interface]") }
    }

    private fun resolveName(uri: Uri) = DeepLinkPolicy.sanitizeTunnelName(
        uri.getQueryParameter("name")
            ?: uri.getQueryParameter("tunnel")
            ?: uri.getQueryParameter("profile")
            ?: uri.lastPathSegment
    )

    private fun decodeBase64(text: String): String {
        val bytes = try {
            Base64.decode(DeepLinkPolicy.normalizeBase64(text), Base64.DEFAULT)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Config is not valid base64", e)
        }
        return String(bytes, StandardCharsets.UTF_8)
    }

    private suspend fun downloadConfig(url: String) = withContext(Dispatchers.IO) {
        val parsed = URL(url)
        // The cast below would reject anything else anyway, but as a ClassCastException with
        // no useful message. Be explicit about what is accepted.
        if (parsed.protocol !in DOWNLOAD_PROTOCOLS)
            throw IllegalArgumentException("Unsupported config URL scheme: ${parsed.protocol}")
        val connection = parsed.openConnection() as HttpURLConnection
        connection.connectTimeout = DOWNLOAD_TIMEOUT_MS
        connection.readTimeout = DOWNLOAD_TIMEOUT_MS
        try {
            val responseCode = connection.responseCode
            if (responseCode !in 200..299)
                throw IOException("HTTP $responseCode")
            String(connection.inputStream.readLimited(MAX_CONFIG_BYTES), StandardCharsets.UTF_8)
        } finally {
            connection.disconnect()
        }
    }

    private fun InputStream.readLimited(maxBytes: Int): ByteArray {
        use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(4096)
            var total = 0
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                total += read
                if (total > maxBytes)
                    throw IOException("Config is too large")
                output.write(buffer, 0, read)
            }
            return output.toByteArray()
        }
    }

    private fun resolveAutoDeleteAtMillis(uri: Uri, metadata: DeepLinkPolicy.Metadata, now: Long): Long? {
        uri.getQueryParameter("delete_after")?.let { return DeepLinkPolicy.expiryFromDuration(now, it) }
        uri.getQueryParameter("delete_in")?.let { return DeepLinkPolicy.expiryFromDuration(now, it) }
        uri.getQueryParameter("ttl")?.let { return DeepLinkPolicy.expiryFromDuration(now, it) }
        uri.getQueryParameter("delete_at")?.let { return DeepLinkPolicy.parseTimestampMillis(it) }
        uri.getQueryParameter("expires_at")?.let { return DeepLinkPolicy.parseTimestampMillis(it) }
        uri.getQueryParameter("expires")?.let { return DeepLinkPolicy.parseTimestampMillis(it) }
        return metadata.deleteAtMillis
    }

    private fun describeUri(uri: Uri): String {
        val path = uri.encodedPath.orEmpty()
        val queryNames = uri.queryParameterNames
            .sorted()
            .joinToString("&") { "$it=<redacted>" }
        return buildString {
            append(uri.scheme ?: "<no-scheme>")
            append("://")
            append(uri.host.orEmpty())
            append(path)
            if (queryNames.isNotEmpty()) {
                append('?')
                append(queryNames)
            }
            if (!uri.fragment.isNullOrEmpty())
                append("#<redacted>")
        }
    }

    private val SUPPORTED_SCHEMES = setOf("ninjawg")
    private val DOWNLOAD_PROTOCOLS = setOf("http", "https")
    private const val TAG = "WG/DeepLinkTunnelImporter"
    private const val DOWNLOAD_TIMEOUT_MS = 10000
    private const val MAX_CONFIG_BYTES = 64 * 1024
}
