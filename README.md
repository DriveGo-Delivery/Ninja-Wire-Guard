# Ninja WG

Ninja WG is an Android WireGuard client with browser deep link support.

- App name: `Ninja WG`
- Package name: `com.ninja.wireguard`
- Deep link scheme: `ninjawg://`

The app can import or update a WireGuard `.conf` file from a browser deep link,
activate the tunnel immediately, and optionally delete the tunnel after a
configured time.

## Build

APK:

```sh
./gradlew :ui:assembleRelease
```

AAB:

```sh
./gradlew :ui:bundleRelease
```

Default output paths:

```text
ui/build/outputs/apk/release/
ui/build/outputs/bundle/release/
```

Release APKs and AABs must be signed with the same release key for every
update.

## Deep Links

Supported deep links:

```text
ninjawg://import
ninjawg://apply
```

Provide the config with one of these methods.

| Parameter | Description |
| --- | --- |
| `url` | URL-encoded `.conf` file URL |
| `conf` | URL-encoded raw WireGuard config |
| `config` | Same as `conf` |
| `conf_b64` | Base64 encoded config (standard or URL-safe alphabet) |
| `config_b64` | Same as `conf_b64` |
| URL fragment | Raw config text containing `[Interface]` — direct `ninjawg://` links only |

The URL fragment method cannot be combined with the `intent://` form below: in an
`intent:` URI everything after `#` is the Intent parameter block, so there is no
fragment left to carry a config. Use `conf`, `conf_b64` or `url` with `intent://`.

Direct scheme example:

```text
ninjawg://import?name=demo&url=https%3A%2F%2Fexample.com%2Fdemo.conf&delete_after=10m
```

Browser/HTML example:

```html
<a href="intent://import?name=demo&url=https%3A%2F%2Fexample.com%2Fdemo.conf&delete_after=10m#Intent;scheme=ninjawg;package=com.ninja.wireguard;end">
  Apply Ninja WG
</a>
```

For Android browsers, the `intent://...#Intent;...;end` form is recommended
because it targets the package directly.

## Deep Link Parameters

### Tunnel Name

Use one of these parameters:

```text
name=demo
tunnel=demo
profile=demo
```

If no name is provided, the default name is `wg`.

Special characters are replaced with `_`, and a `.conf` suffix is removed.

### Immediate Activation

The default is `true`, so imported tunnels are turned on immediately.

Disable immediate activation:

```text
activate=0
start=0
up=0
```

Enable immediate activation explicitly:

```text
activate=1
start=true
up=yes
```

Accepted true values:

```text
1, true, yes, on
```

Accepted false values:

```text
0, false, no, off
```

### Auto Delete

Delete the tunnel after a duration:

```text
delete_after=10m
delete_in=1h
ttl=7d
```

Delete the tunnel at a specific time:

```text
delete_at=2026-05-08T12:00:00Z
expires_at=2026-05-08T12:00:00Z
expires=1778236800
```

Supported duration units:

| Unit | Meaning |
| --- | --- |
| *(omitted)* | seconds |
| `s`, `sec`, `secs`, `second`, `seconds` | seconds |
| `m`, `min`, `mins`, `minute`, `minutes` | minutes |
| `h`, `hr`, `hrs`, `hour`, `hours` | hours |
| `d`, `day`, `days` | days |

Timestamps can be Unix seconds, Unix milliseconds, or ISO-8601 UTC strings.
ISO-8601 values need an explicit offset (`2026-05-08T12:00:00Z`, not
`2026-05-08T12:00:00`). A timestamp already in the past deletes the tunnel as soon
as it has finished being imported and activated.

Expiry is enforced by an alarm. Android only grants exact alarms on request, so
without that grant the deletion can be delayed while the device is dozing, and a
force-stop drops pending alarms entirely. The app therefore also deletes anything
past due whenever it is brought to the foreground.

## Config Metadata Syntax

Ninja WG metadata can be embedded in the `.conf` file as comments. These lines
are removed before the WireGuard parser runs, so the actual config remains a
valid normal WireGuard config.

Example:

```conf
# NinjaWG-Activate: true
# NinjaWG-Delete-After: 10m

[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.66.66.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
AllowedIPs = 10.66.66.1/32
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

Supported metadata keys:

```text
NinjaWG-Activate
NinjaWG-Up
NinjaWG-Start
NinjaWG-Delete-After
NinjaWG-Auto-Delete-After
NinjaWG-TTL
NinjaWG-Delete-At
NinjaWG-Expires-At
NinjaWG-Expires
```

Both `#` and `;` comment prefixes are supported.

```conf
; NinjaWG-Delete-After: 30m
```

Plain `;` comment lines are also stripped before parsing, because the WireGuard
config parser itself only understands `#`.

## Priority

Deep link parameters override config metadata.

Example:

```text
ninjawg://import?name=demo&url=https%3A%2F%2Fexample.com%2Fdemo.conf&activate=0&delete_after=30m
```

If the linked config contains `# NinjaWG-Activate: true`, the tunnel still will
not be activated immediately because `activate=0` is set in the deep link.

## Full Example

HTML:

```html
<a href="intent://import?name=demo&url=https%3A%2F%2Fexample.com%2Fdemo.conf&activate=1&delete_after=30m#Intent;scheme=ninjawg;package=com.ninja.wireguard;end">
  Apply 30-minute tunnel
</a>
```

Config:

```conf
# NinjaWG-Activate: true
# NinjaWG-Delete-After: 30m

[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.66.66.2/32

[Peer]
PublicKey = SERVER_PUBLIC_KEY
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820
PersistentKeepalive = 25
```

## Notes

- `url` values must be URL-encoded.
- If Android VPN permission has not been granted yet, the app opens the VPN
  permission prompt.
- If the tunnel turns on but traffic shows `RX 0 B`, check server peer
  registration, public/private keys, endpoint, firewall, and `AllowedIPs`.
  That is a WireGuard handshake issue, not a deep link issue.
