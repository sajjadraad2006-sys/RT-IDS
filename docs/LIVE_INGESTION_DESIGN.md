# Safe live-ingestion direction (not implemented)

CyberGuard remains an analyzer for uploaded flow and IDS log records.
Offline Suricata EVE log ingestion is now implemented via the dedicated
evidence bridge documented in [`docs/SURICATA_EVIDENCE_BRIDGE.md`](SURICATA_EVIDENCE_BRIDGE.md).
Live continuous socket/sensor daemon ingestion remains intentionally unimplemented
until independently evaluated live sensor adapters exist.

## Proposed next adapter: local Zeek `conn.log` JSON

The adapter must read an already-authorized local JSON log or Unix socket. It
must not request packet-capture privileges, start Zeek, choose an interface, or
target any public system.

```text
Zeek-owned conn.log JSON
  -> source reader + inode/offset checkpoint
  -> bounded conversion queue
  -> explicit Zeek-to-flow schema adapter
  -> FlowSchemaValidator
  -> fixed Pipeline v2 inference batch
  -> bounded alert persistence / analyst review
```

## Conversion contract

The adapter needs a separately versioned mapping such as
`cyberguard-zeek-conn-adapter-v1`. It may derive only values justified by Zeek
fields and units. For example, duration and originator/responder byte/packet
counts can map to flow duration/forward/backward totals after a documented
direction rule. TCP flag counts, packet-length distributions, window sizes,
IAT, active, and idle features are not present in ordinary `conn.log` and must
not default to zero.

Because the current model requires all 32 features, plain Zeek `conn.log` is
not yet compatible. Deployment needs either:

1. an enriched, tested telemetry source that supplies/derives the full schema;
   or
2. a separately trained and independently evaluated artifact with an explicit
   Zeek coverage contract and its own feature schema/version.

This incompatibility must return unhealthy/unsupported, never silent zero-fill.

## Bounded queue and backpressure

- A fixed maximum queue length and batch size are configuration, not unbounded
  lists.
- On queue saturation, pause the source when possible. If the source cannot be
  paused, write a bounded dead-letter reference or increment an explicit
  dropped-record counter with first/last source offsets.
- Never report healthy while records are being discarded.
- Persistence uses the same per-batch transaction and configured alert cap as
  uploads; source records are not copied wholesale into the database.

## Offsets, reconnect and loss accounting

- For files: checkpoint device/inode, byte offset and last complete JSON event
  atomically after a committed batch. Detect rotation/truncation and expose it.
- For sockets: use exponential reconnect backoff with a cap and jitter; expose
  disconnected duration and reconnect attempts.
- Reject partial JSON at EOF until it is completed. Malformed records increment
  rejected/dead-letter counts and include a bounded reason, never raw sensitive
  content.
- On restart, resume from the last committed offset. If the source history is
  unavailable, report an explicit gap.

## Required health surface

```json
{
  "source_kind": "zeek_conn_json",
  "adapter_version": "cyberguard-zeek-conn-adapter-v1",
  "connected": false,
  "schema_compatible": false,
  "queue_depth": 0,
  "queue_capacity": 10000,
  "last_source_offset": null,
  "last_committed_offset": null,
  "accepted": 0,
  "rejected": 0,
  "dropped": 0,
  "reconnect_attempts": 0,
  "last_error": "full 32-feature contract unavailable"
}
```

## Tests required before enabling

- golden conversion rows with unit/direction checks;
- unsupported/missing fields fail closed;
- queue saturation, pause and drop accounting;
- file rotation, truncation, partial writes, restart and offset recovery;
- socket disconnect/reconnect and backoff;
- stable source-to-result ordering across batches;
- no raw network identifiers in prompts or unnecessary persistence;
- throughput and memory on a local recorded fixture, described as sensor-log
  processing rather than packet line rate.

Until these conditions and independent model evaluation are complete, no live
navigation, health badge, or deployment text should imply that a sensor is
connected. Any future sensor dataset must first satisfy
`docs/INDEPENDENT_EVALUATION.md`; sensor integration is not permission to reuse
calibration or final-evaluation captures across roles.

## Implemented Live Operations polling

The UI now implements bounded four-second polling of persisted backend state;
this does not implement the privileged sensor adapter described above. The
controller pauses while the page is hidden, has a single in-flight request,
aborts superseded manual refreshes, ignores stale responses, and deduplicates
within each source independently. Connection/degraded state, last success,
last error, manual refresh, pause/resume, source freshness, incidents, triage,
and risk decomposition are visible.

The API labels flow results `uploaded_not_continuous_ingestion` and Suricata
records `uploaded_eve_not_sensor_stream`. A future Zeek or continuous Suricata
adapter must still satisfy the queue/backpressure/offset contract in this
document before its state can be labeled connected or live.
