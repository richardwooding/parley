# parley

Croc-style pairing for long-lived, end-to-end-encrypted group sessions. A
host gets a code phrase (`lion-42-maple`); others join with it. A relay —
hosted anywhere, one `http.Handler` — forwards frames it can never read.

parley is the extracted session core of
[kibitz](https://github.com/richardwooding/kibitz), where it carries chat and
thirteen board games between browsers.

## How it works

- **The phrase is the secret.** It seeds a PAKE handshake
  (schollz/pake/v3, curve "siec" — croc's default) between each joiner and
  the host; the relay only ever sees `SHA-256(label ∥ phrase)[:16]`, so it
  cannot even attempt to join.
- **One group key, wrapped per member.** The host wraps a random 32-byte
  group key to each joiner under the PAKE-derived pairwise key
  (HKDF-SHA256). All traffic is XChaCha20-Poly1305 with associated data
  binding session, protocol version, and sender — no cross-session replay,
  no sender reflection.
- **Leavers are locked out.** Any departure rotates the group key to the
  survivors. If the *host* leaves, a survivor is promoted and the rest
  re-PAKE with it; a short previous-key ring keeps in-flight frames
  decryptable across the swap.
- **The relay is blind and dumb.** Session IDs, participant counts, opaque
  frames. Unexpected drops hold the slot for a grace window so clients can
  resume; clean leaves are final.

## Usage

```go
// Server: mount the relay anywhere.
srv := relay.New(relay.Options{})
http.Handle("/ws", srv)

// Host: create a session, share the phrase out of band.
client, phrase, err := session.Host(ctx, "wss://example.com/ws")

// Joiner: pair with the phrase.
client, err := session.Join(ctx, "wss://example.com/ws", phrase)

// Both ends: encrypted app frames by service ID.
client.Broadcast("chat", body)
for ev := range client.Events() { /* Frame, MemberKeyed, MemberLeft, Closed */ }
```

## Protocol labels

Every end of a session must agree on an application label — it
domain-separates the session-ID hash and the PAKE key schedule:

```go
session.Host(ctx, url, session.WithProtocol("myapp/v1"))
```

The default is `"parley/v1"`. **Changing an application's label is a
protocol version bump**: ends with different labels derive different session
IDs and keys and cannot talk. (kibitz's deployed label is `"kibitz/v1"`;
both derivations are pinned by golden tests.)

## Services

The `service` package multiplexes application services over one session:
implement `service.Service` (ID/HandleFrame/Snapshot/Restore), register with
`service.NewMux(client, service.WithServices(...))`, and get a
host-authoritative roster with display names, snapshot catch-up for late
joiners, per-sender sequence tracking, and host-migration election
(`WithSuccessor` for custom policies). `service/chat` is a ready-made text
chat with deduped late-join history.

## Notes

- `session` (and `wire`/`crypto`/`phrase`) compile to `GOOS=js GOARCH=wasm`;
  the relay is server-side only.
- Reconnect = resume for network drops (relay holds the slot for a grace
  window); otherwise rejoin with the phrase.
- Roles are pluggable: the host's `RolePolicy` (see `WithRolePolicy`)
  assigns each keyed joiner a role byte that rides inside the encrypted
  handshake — values 2..255 are the application's vocabulary. The default
  policy seats `WithObserver` joiners as `RoleObserver` and everyone else
  as `RoleMember`. Pass the policy to `Join` too: a joiner promoted by
  host migration becomes the role assigner.

MIT licensed.
