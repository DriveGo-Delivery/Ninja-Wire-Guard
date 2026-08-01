/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import com.wireguard.android.backend.Tunnel
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * The parsing rules behind the `ninjawg://` deep link, kept free of Android dependencies so
 * they can be unit-tested directly. Every value handled here arrives from an untrusted link,
 * so the edges — overflow, both base64 alphabets, comment syntax — are the point.
 */
internal object DeepLinkPolicy {
    data class Metadata(val activate: Boolean?, val deleteAtMillis: Long?)

    const val DEFAULT_TUNNEL_NAME = "wg"

    fun sanitizeTunnelName(rawName: String?): String {
        val candidate = rawName ?: return DEFAULT_TUNNEL_NAME
        val sanitized = candidate.substringAfterLast('/')
            .removeSuffix(".conf")
            .replace(UNSAFE_NAME_CHARS, "_")
            // Truncate before trimming, so a cut that lands on a separator does not leave
            // one dangling at the end of the name.
            .take(Tunnel.NAME_MAX_LENGTH)
            .trim { it == '_' || it == '.' || it == '-' }
        return sanitized.takeIf { it.isNotEmpty() && !Tunnel.isNameInvalid(it) } ?: DEFAULT_TUNNEL_NAME
    }

    fun parseBoolean(rawValue: String?) = when (rawValue?.trim()?.lowercase()) {
        "1", "true", "yes", "on" -> true
        "0", "false", "no", "off" -> false
        else -> null
    }

    fun parseDurationMillis(rawValue: String): Long {
        val match = DURATION_PATTERN.matchEntire(rawValue.trim())
            ?: throw IllegalArgumentException("Invalid duration: $rawValue")
        val amount = match.groupValues[1].toLongOrNull()
            ?: throw IllegalArgumentException("Duration is too large: $rawValue")
        val multiplier = when (match.groupValues[2].lowercase()) {
            "", "s", "sec", "secs", "second", "seconds" -> 1000L
            "m", "min", "mins", "minute", "minutes" -> 60_000L
            "h", "hr", "hrs", "hour", "hours" -> 3_600_000L
            "d", "day", "days" -> 86_400_000L
            else -> throw IllegalArgumentException("Invalid duration unit: $rawValue")
        }
        require(amount > 0) { "Duration must be positive" }
        return try {
            Math.multiplyExact(amount, multiplier)
        } catch (e: ArithmeticException) {
            throw IllegalArgumentException("Duration is too large: $rawValue", e)
        }
    }

    /**
     * Turns a duration into an absolute expiry. The addition is checked because an unchecked
     * one wraps a very large TTL into a timestamp in the past, which reads as "already
     * expired" and deletes the tunnel immediately — the opposite of what was asked for.
     */
    fun expiryFromDuration(now: Long, rawValue: String): Long {
        val durationMillis = parseDurationMillis(rawValue)
        return try {
            Math.addExact(now, durationMillis)
        } catch (e: ArithmeticException) {
            throw IllegalArgumentException("Duration is too far in the future: $rawValue", e)
        }
    }

    fun parseTimestampMillis(rawValue: String): Long {
        val value = rawValue.trim()
        value.toLongOrNull()?.let { numeric ->
            if (numeric >= SECONDS_UPPER_BOUND) return numeric
            return try {
                Math.multiplyExact(numeric, 1000L)
            } catch (e: ArithmeticException) {
                throw IllegalArgumentException("Timestamp is out of range: $rawValue", e)
            }
        }
        return try {
            Instant.parse(value).toEpochMilli()
        } catch (e: DateTimeParseException) {
            throw IllegalArgumentException("Invalid timestamp: $rawValue", e)
        } catch (e: ArithmeticException) {
            // Instant accepts years far outside what fits in epoch milliseconds.
            throw IllegalArgumentException("Timestamp is out of range: $rawValue", e)
        }
    }

    fun parseMetadata(configText: String, now: Long): Metadata {
        var activate: Boolean? = null
        var deleteAtMillis: Long? = null
        configText.lineSequence().forEach { line ->
            val match = METADATA_PATTERN.matchEntire(line) ?: return@forEach
            val value = match.groupValues[2]
            when (match.groupValues[1].lowercase()) {
                "activate", "up", "start" -> activate = parseBoolean(value)
                "delete-after", "auto-delete-after", "ttl" -> deleteAtMillis = expiryFromDuration(now, value)
                "delete-at", "expires-at", "expires" -> deleteAtMillis = parseTimestampMillis(value)
            }
        }
        return Metadata(activate, deleteAtMillis)
    }

    /**
     * Strips the lines the WireGuard parser must not see: Ninja WG metadata, and `;`
     * comments. The upstream parser only understands `#`, so a `;` line reaches it as a
     * syntax error and fails the whole import even though the documented syntax allows it.
     */
    fun stripNonConfigLines(configText: String) =
        configText.lineSequence()
            .filterNot { METADATA_PATTERN.matches(it) || SEMICOLON_COMMENT_PATTERN.matches(it) }
            .joinToString("\n")

    /**
     * Normalizes either base64 alphabet onto the standard one. Senders routinely produce
     * standard base64, and `Uri.getQueryParameter` decodes a literal `+` to a space before
     * the value ever reaches us, so decoding strictly URL-safe rejects most real input.
     */
    fun normalizeBase64(text: String) = text
        .replace(' ', '+')
        .filterNot { it == '\n' || it == '\r' || it == '\t' }
        .replace('-', '+')
        .replace('_', '/')

    private val UNSAFE_NAME_CHARS = Regex("[^A-Za-z0-9_=+.-]")
    private val DURATION_PATTERN = Regex("^(\\d+)\\s*([a-zA-Z]*)$")
    private val SEMICOLON_COMMENT_PATTERN = Regex("^\\s*;.*$")
    private val METADATA_PATTERN = Regex(
        "^\\s*[#;]\\s*NinjaWG-(Activate|Up|Start|Delete-After|Auto-Delete-After|TTL|Delete-At|Expires-At|Expires)\\s*:\\s*(.*?)\\s*$",
        RegexOption.IGNORE_CASE
    )
    private const val SECONDS_UPPER_BOUND = 10_000_000_000L
}
