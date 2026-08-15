# Guide: Observability

token-auth-proxy exports OpenTelemetry traces, metrics, and logs, and
has an always-on Prometheus `/metrics` endpoint. For the field-by-field
reference, see the [main README's Observability section](../../README.md#observability).

## The one thing that's always on: `/metrics`

No configuration needed — `GET /metrics` is mounted unauthenticated
from process start, in standard Prometheus exposition format. Point a
scrape config at it directly:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: token-auth-proxy
    static_configs:
      - targets: ["token-auth-proxy:8080"]
```

```sh
curl http://localhost:8080/metrics
```

```
# HELP authn_rejections_total Number of inbound requests rejected by authn, by reason.
# TYPE authn_rejections_total counter
authn_rejections_total{reason="no_credential"} 1
# ... plus standard Go runtime metrics, process metrics, and
# otelhttp's own http.server.request.duration histogram
```

## The custom metric: `authn_rejections_total`

Generic HTTP metrics can tell you a request got a `401`; they can't
tell you *why*. This counter can, attributed by the same `reason`
already used in structured logs: `no_credential`, `malformed_token`,
`unknown_issuer`, `keys_unavailable`, `expired`, `not_yet_valid`,
`bad_signature`, `bad_audience`, `issuer_mismatch`, `invalid_claims`,
`saml_metadata_unavailable`. A few things this makes easy to alert on
or dashboard:

```promql
# Rejection rate by reason, last 5 minutes
sum by (reason) (rate(authn_rejections_total[5m]))

# Are we in a JWKS/IdP-metadata outage right now, as opposed to normal
# client-side rejection noise?
sum(rate(authn_rejections_total{reason=~"keys_unavailable|saml_metadata_unavailable"}[5m])) > 0
```

That second query is the one worth actually alerting on:
`keys_unavailable`/`saml_metadata_unavailable` mean the proxy's own
configured JWKS/IdP-metadata endpoint is unreachable — an
operator-actionable problem, unlike the rest of the reasons, which are
just expected background noise from scanners and misconfigured
clients.

## Traces and logs (and pushing metrics via OTLP)

These are off until you configure them — no YAML/`TAP_` fields, just
the [standard OpenTelemetry environment variables](https://opentelemetry.io/docs/specs/otel/protocol/exporter/)
any OTel-instrumented service already reads. Point at a collector and
the relevant signal turns on:

```sh
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_SERVICE_NAME=token-auth-proxy   # optional, this is already the default

token-auth-proxy --config config.yaml
```

Or turn on just one signal, leaving the others off, via the per-signal
variable:

```sh
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4318
```

Leaving everything unset keeps the proxy fully inert on this front — no
connection attempts, no export-failure log noise, nothing but
`/metrics` and stdout JSON logs.

### Trying it against a real collector locally

The [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector)
has an image that'll just log everything it receives — handy for
seeing your own traces/logs land somewhere real without standing up a
full backend:

```sh
docker run -p 4317:4317 -p 4318:4318 \
  otel/opentelemetry-collector:latest
```

Point `OTEL_EXPORTER_OTLP_ENDPOINT` at it (`http://localhost:4318` for
HTTP, `http://localhost:4317` for gRPC — set
`OTEL_EXPORTER_OTLP_PROTOCOL` to match) and watch the collector's own
stdout as you send requests through the proxy.

## What you get once traces are on

- **Server-side spans** for the proxied route (via `otelhttp`) — not
  `/healthz` or `/metrics`, so probe/scrape traffic doesn't pollute
  traces or double-count in its own request-duration metrics.
- **Client-side spans** for every outbound call to the backend, with
  trace context automatically propagated in the forwarded request's
  headers — if your backend is also OTel-instrumented, its spans link
  up with the proxy's without either side doing anything extra.
- **Log/trace correlation**: request-scoped log lines (rejection logs,
  proxy errors) pick up `trace_id`/`span_id` and get forwarded to the
  OTel Logs SDK, so you can pivot from a trace straight to the log line
  that explains a rejection. Startup/reload/background logs aren't part
  of any request trace and won't carry these fields — that's expected.

Stdout JSON logging via `slog` keeps its exact existing shape either
way; log export via OTLP is additive, not a replacement.

## A note on dependency footprint

Wiring in the OTel SDK, its OTLP exporters, and
`prometheus/client_golang` is a meaningfully larger set of dependencies
than the rest of this project takes on — an accepted cost of speaking
the real OTLP wire protocol rather than a lighter, non-standard
alternative. If you never set any `OTEL_*` env var, none of that
machinery does anything beyond serving `/metrics`.
