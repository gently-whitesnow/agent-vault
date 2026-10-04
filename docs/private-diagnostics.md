# Private delivery diagnostics, wire version 1

`POST /v1/vaults/{name}/diagnostics` is a narrow, no-store management operation.
The existing instance identity must have an explicit admin membership in the
selected vault. A scoped proxy token cannot call it. The selected recipient must
have a current vault membership; a proxy-only agent may retain its normal
`no-access` instance role. Neither its token nor a new grant is used.

Request fields (unknown fields and trailing JSON are rejected, 16 KiB limit):

```json
{"version":1,"operation":"evidence","service":"telegram","keys":["TOKEN"],"recipient_id":"existing-agent-uuid","recipient_type":"agent","opt_in":false}
```

`keys` must exactly equal the selected enabled rule's credential key set.
`recipient_type` is `agent` or `user`. `operation` is `evidence` or
`telegram_get_me`; the latter additionally requires `opt_in:true`.
No destination, headers, body, credential values or expected fingerprints are
accepted from the caller.

The response contains `version`, `vault`, `service`, `keys`, `loaded`,
`recipient_ingress`, and optionally `management_probe`. Each evidence result has:

- `state`: `matched`, `mismatch`, `not_checked` or `unavailable`, with an optional
  machine `reason`. This compares actual imported/loaded/used values to the
  observed Bao copy, **not** the Ecosystem store. The caller must compare that
  separately and check its own current secret grant before and after the request.
- `fields`: the selected loaded/used values' full SHA256 and `utf8_bytes`.
  `copy_fields`: the same selected keys observed directly from Bao. These are
  sensitive private evidence, never catalogue, settings, timeline or log data.
- `copy_version`, `copy_observed_at`, `imported_copy_version`, `import_id`,
  `snapshot_id`, `loaded_at`. KV1 has a null version. `snapshot_id` identifies
  the exact encrypted row set read atomically with its rule; it is not an
  Ecosystem store version. All counters are independent.
- For real ingress: `used_at`, `actor_kind=recipient_ingress`, `actor_type`,
  `actor_id`, `request_id`. No observation is `not_checked`, never an inferred use.

`management_probe` has `category`, `request_id` and, when forwarding occurred,
`evidence` with `actor_kind=management_probe` and the actual management actor.
An admin probe is never recorded as recipient ingress. It does not prove that
the recipient's runtime has configured its proxy correctly.

Only an existing Telegram passthrough rule with one path substitution supports
the probe. It calls fixed HTTPS GET `/bot<token>/getMe` through the shared
resolve/inject/substitute/forward path. The substituted token shape and final
method/host/path are checked. The dial accepts only validated public Telegram
DNS answers, connects to the selected IP without resolving it again, and ignores
private-range overrides. Redirects are not followed. Total time is at most ten
seconds; response data is bounded to 64 KiB. Only categories such as `ok`,
`rejected`, `unsupported`, `unavailable`, `timeout`, `rate_limited`,
`redirect_blocked`, `forbidden_request` (local refusal before dialing), and `response_too_large` leave the boundary. Bot identity,
response bodies and upstream error text are not returned or logged.

Evidence is held only in a bounded in-memory registry (256 records per channel, at most 256 fields per record,
five-minute TTL), never general request logs. After restart/expiration it stays
unavailable until a real import/request provides new evidence. The import marker
is published only after successful guarded atomic replacement and is bound to
its exact ciphertext set. Missing markers fail closed. Reads may observe a
historical snapshot; timestamps/versions qualify the observation. A source/rule
or membership change during the operation returns 409. Recipient observations
predating its current membership are not reused. Unsupported/old servers return
no capability; callers must not invent a successful comparison.

Tests use only synthetic SQLite identities/credentials, an isolated KV fixture
and a TLS upstream fixture. They never mutate production secrets or memberships.

Ingress observations currently cover the MITM HTTP forwarding path only.
WebSocket upgrades and non-MITM paths remain `not_checked`. `used_at` is the
registry timestamp recorded once upstream headers arrive; it is not a TCP
send timestamp. The management probe returns that same recorded timestamp.
Import markers expire after five minutes: with a longer sync interval, provenance
can be `unavailable` between syncs even while credential use still works. This is
missing evidence, not a failed credential or a reason to restart the proxy.
