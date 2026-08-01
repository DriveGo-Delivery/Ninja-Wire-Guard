/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class DeepLinkPolicyTest {
    // ---- tunnel names -----------------------------------------------------------------

    @Test
    fun `name falls back to the default when absent or unusable`() {
        assertEquals("wg", DeepLinkPolicy.sanitizeTunnelName(null))
        assertEquals("wg", DeepLinkPolicy.sanitizeTunnelName(""))
        assertEquals("wg", DeepLinkPolicy.sanitizeTunnelName("___"))
        assertEquals("wg", DeepLinkPolicy.sanitizeTunnelName("...conf"))
    }

    @Test
    fun `name drops directories and the conf suffix`() {
        assertEquals("demo", DeepLinkPolicy.sanitizeTunnelName("demo.conf"))
        assertEquals("demo", DeepLinkPolicy.sanitizeTunnelName("/a/b/demo.conf"))
    }

    @Test
    fun `name replaces disallowed characters`() {
        assertEquals("my_vpn", DeepLinkPolicy.sanitizeTunnelName("my vpn"))
        assertEquals("a_b", DeepLinkPolicy.sanitizeTunnelName("a:b"))
        // Non-ASCII collapses to separators, which then trim away entirely.
        assertEquals("wg", DeepLinkPolicy.sanitizeTunnelName("한글"))
    }

    @Test
    fun `name truncates then trims so no separator is left dangling`() {
        // 15 chars of payload plus a separator that the cut would otherwise expose.
        val name = DeepLinkPolicy.sanitizeTunnelName("abcdefghijklmno_pqr")
        assertEquals("abcdefghijklmno", name)
        assertEquals(15, name.length)

        val cutOnSeparator = DeepLinkPolicy.sanitizeTunnelName("abcdefghijklmn_xyz")
        assertEquals("abcdefghijklmn", cutOnSeparator)
        assertFalse(cutOnSeparator.endsWith("_"))
    }

    // ---- booleans ---------------------------------------------------------------------

    @Test
    fun `boolean accepts the documented spellings and rejects everything else`() {
        listOf("1", "true", "TRUE", "yes", "on", " On ").forEach {
            assertTrue("expected true for '$it'", DeepLinkPolicy.parseBoolean(it)!!)
        }
        listOf("0", "false", "FALSE", "no", "off").forEach {
            assertFalse("expected false for '$it'", DeepLinkPolicy.parseBoolean(it)!!)
        }
        // null means "no opinion", so the caller can fall through to the next source.
        assertNull(DeepLinkPolicy.parseBoolean(null))
        assertNull(DeepLinkPolicy.parseBoolean(""))
        assertNull(DeepLinkPolicy.parseBoolean("maybe"))
    }

    // ---- durations -------------------------------------------------------------------

    @Test
    fun `duration units`() {
        assertEquals(30_000L, DeepLinkPolicy.parseDurationMillis("30"))
        assertEquals(30_000L, DeepLinkPolicy.parseDurationMillis("30s"))
        assertEquals(30_000L, DeepLinkPolicy.parseDurationMillis("30 seconds"))
        assertEquals(600_000L, DeepLinkPolicy.parseDurationMillis("10m"))
        assertEquals(3_600_000L, DeepLinkPolicy.parseDurationMillis("1h"))
        assertEquals(604_800_000L, DeepLinkPolicy.parseDurationMillis("7d"))
        assertEquals(600_000L, DeepLinkPolicy.parseDurationMillis(" 10 MIN "))
    }

    @Test
    fun `duration rejects junk, zero and unknown units`() {
        listOf("", "abc", "-5m", "5x", "1.5h", "10 m 30 s").forEach {
            assertThrows(IllegalArgumentException::class.java) { DeepLinkPolicy.parseDurationMillis(it) }
        }
        assertThrows(IllegalArgumentException::class.java) { DeepLinkPolicy.parseDurationMillis("0") }
    }

    @Test
    fun `duration overflow is rejected rather than wrapped`() {
        assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.parseDurationMillis("9223372036854775807d")
        }
        // More digits than a Long holds.
        assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.parseDurationMillis("99999999999999999999s")
        }
    }

    // ---- expiry from duration --------------------------------------------------------

    @Test
    fun `expiry adds the duration to now`() {
        assertEquals(1_000_600_000L, DeepLinkPolicy.expiryFromDuration(1_000_000_000L, "10m"))
    }

    @Test
    fun `expiry rejects the overflow that would flip a long TTL into the past`() {
        // Passes the checked multiply (just under Long.MAX) but overflows once added to now,
        // which an unchecked addition would turn into "already expired" — deleting immediately.
        val huge = "9223372036854775s"
        assertEquals(9_223_372_036_854_775_000L, DeepLinkPolicy.parseDurationMillis(huge))
        val e = assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.expiryFromDuration(System.currentTimeMillis(), huge)
        }
        assertTrue(e.message!!.contains("too far in the future"))
    }

    // ---- timestamps ------------------------------------------------------------------

    @Test
    fun `timestamp treats small numbers as seconds and large ones as milliseconds`() {
        assertEquals(1_778_236_800_000L, DeepLinkPolicy.parseTimestampMillis("1778236800"))
        assertEquals(1_778_236_800_000L, DeepLinkPolicy.parseTimestampMillis("1778236800000"))
        // Boundary: below is seconds, at or above is already milliseconds.
        assertEquals(9_999_999_999_000L, DeepLinkPolicy.parseTimestampMillis("9999999999"))
        assertEquals(10_000_000_000L, DeepLinkPolicy.parseTimestampMillis("10000000000"))
    }

    @Test
    fun `timestamp parses ISO-8601 instants`() {
        assertEquals(1_778_241_600_000L, DeepLinkPolicy.parseTimestampMillis("2026-05-08T12:00:00Z"))
        assertEquals(1_778_241_600_000L, DeepLinkPolicy.parseTimestampMillis(" 2026-05-08T12:00:00Z "))
    }

    @Test
    fun `timestamp rejects junk and out-of-range values`() {
        // No offset is not a valid Instant.
        assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.parseTimestampMillis("2026-05-08T12:00:00")
        }
        assertThrows(IllegalArgumentException::class.java) { DeepLinkPolicy.parseTimestampMillis("tomorrow") }
        assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.parseTimestampMillis("+1000000000-12-31T23:59:59Z")
        }
        // Scaling seconds to milliseconds must not wrap past Long.MIN either.
        assertThrows(IllegalArgumentException::class.java) {
            DeepLinkPolicy.parseTimestampMillis("-9223372036854776")
        }
    }

    @Test
    fun `an explicitly past timestamp is accepted and means delete now`() {
        assertEquals(0L, DeepLinkPolicy.parseTimestampMillis("0"))
        assertEquals(-5_000L, DeepLinkPolicy.parseTimestampMillis("-5"))
    }

    // ---- metadata --------------------------------------------------------------------

    private val configWithMetadata = """
        # NinjaWG-Activate: false
        ; NinjaWG-Delete-After: 30m
        ; a plain semicolon comment
        # a plain hash comment

        [Interface]
        PrivateKey = aGVsbG8=
    """.trimIndent()

    @Test
    fun `metadata is read from both comment prefixes and is case-insensitive`() {
        val metadata = DeepLinkPolicy.parseMetadata(configWithMetadata, now = 1_000L)
        assertFalse(metadata.activate!!)
        assertEquals(1_000L + 1_800_000L, metadata.deleteAtMillis)

        val upper = DeepLinkPolicy.parseMetadata("#ninjawg-ttl:1h", now = 0L)
        assertEquals(3_600_000L, upper.deleteAtMillis)
    }

    @Test
    fun `metadata absent leaves both fields unset so callers can fall through`() {
        val metadata = DeepLinkPolicy.parseMetadata("[Interface]\nPrivateKey = aGVsbG8=", now = 0L)
        assertNull(metadata.activate)
        assertNull(metadata.deleteAtMillis)
    }

    @Test
    fun `stripping removes metadata and semicolon comments but keeps the config`() {
        val stripped = DeepLinkPolicy.stripNonConfigLines(configWithMetadata)
        assertFalse(stripped.contains("NinjaWG"))
        // The upstream parser has no notion of ';' — a survivor here is a syntax error there.
        assertFalse(stripped.contains(";"))
        assertTrue(stripped.contains("[Interface]"))
        assertTrue(stripped.contains("PrivateKey = aGVsbG8="))
        // '#' comments are the parser's own business and are left alone.
        assertTrue(stripped.contains("# a plain hash comment"))
    }

    @Test
    fun `stripping handles CRLF input`() {
        val stripped = DeepLinkPolicy.stripNonConfigLines("; NinjaWG-TTL: 1h\r\n[Interface]\r\nPrivateKey = x\r\n")
        assertFalse(stripped.contains("NinjaWG"))
        // Carriage returns must not survive into the text handed to the parser.
        assertFalse(stripped.contains("\r"))
        assertEquals(listOf("[Interface]", "PrivateKey = x"), stripped.lines().filter { it.isNotEmpty() })
    }

    // ---- base64 ----------------------------------------------------------------------

    @Test
    fun `base64 normalizes both alphabets onto the standard one`() {
        assertEquals("ab+/cd==", DeepLinkPolicy.normalizeBase64("ab-_cd=="))
        assertEquals("ab+/cd==", DeepLinkPolicy.normalizeBase64("ab+/cd=="))
    }

    @Test
    fun `base64 recovers plus signs that query decoding turned into spaces`() {
        // Uri.getQueryParameter decodes a literal '+' to a space before we ever see it.
        assertEquals("ab+cd+ef", DeepLinkPolicy.normalizeBase64("ab cd ef"))
    }

    @Test
    fun `base64 tolerates wrapped input`() {
        assertEquals("abcdefgh", DeepLinkPolicy.normalizeBase64("abcd\r\nefgh"))
        assertEquals("abcdefgh", DeepLinkPolicy.normalizeBase64("abcd\tefgh"))
    }
}
