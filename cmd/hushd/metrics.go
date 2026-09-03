package main

import "github.com/prometheus/client_golang/prometheus"

// Metrics are hush's own series, registered on the chassis's private registry
// via chassis.Config.Collectors so /metrics is one scrape.
//
// Cardinality rule applied throughout: NO label ever carries a secret id, a
// client IP, or a URL path. A metric label lands in the time series index and
// stays there, so a per-secret label would be both a capability leak and an
// unbounded index. Every label below is a closed enum.
type Metrics struct {
	Created  prometheus.Counter
	Revealed *prometheus.CounterVec // result: ok | gone
	Rejected *prometheus.CounterVec // reason: closed enum, see rejection reasons
	Bytes    prometheus.Histogram
	StoreUp  prometheus.Gauge
	Limited  prometheus.Counter
}

// Rejection reasons. A closed set, mirrored by the API error codes, so
// `hush_secrets_rejected_total{reason="ciphertext_too_large"}` and the 422 a
// caller saw are the same vocabulary.
const (
	reasonTooLarge  = "ciphertext_too_large"
	reasonInvalid   = "ciphertext_invalid"
	reasonEmpty     = "ciphertext_empty"
	reasonTTL       = "ttl_out_of_range"
	reasonMalformed = "malformed_request"
)

func newMetrics() *Metrics {
	return &Metrics{
		Created: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hush_secrets_created_total",
			Help: "Secrets accepted and stored.",
		}),
		Revealed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hush_secrets_revealed_total",
			Help: "Reveal attempts by outcome. `gone` covers already-revealed, expired, never-existed and evicted, which the service does not distinguish.",
		}, []string{"result"}),
		Rejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hush_secrets_rejected_total",
			Help: "Create attempts refused by validation, by reason.",
		}, []string{"reason"}),
		Bytes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "hush_secret_ciphertext_bytes",
			Help: "Size of stored ciphertext.",
			// Hand-picked rather than DefBuckets (which tops out at 10): this
			// measures bytes up to a 64 KiB cap, so the buckets straddle
			// credential-sized (hundreds of bytes) through the limit.
			Buckets: []float64{256, 1024, 4096, 16384, 65536},
		}),
		StoreUp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hush_store_up",
			Help: "1 when the last readiness probe reached Redis, 0 otherwise.",
		}),
		Limited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hush_rate_limited_total",
			Help: "Requests refused by the create rate limit. A sustained rise is the abuse signal.",
		}),
	}
}

// Collectors is what gets handed to chassis.Config.Collectors. The chassis owns
// a private registry and exposes no accessor, so this slice is the only way
// hush's series reach /metrics.
func (m *Metrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.Created, m.Revealed, m.Rejected, m.Bytes, m.StoreUp, m.Limited}
}

// Prime initialises the label combinations that alerting queries reference.
//
// Without this, `rate(hush_secrets_revealed_total{result="gone"}[15m])` returns
// no data until the first `gone` ever happens, and an alert written against a
// missing series is an alert that cannot fire. Priming makes the series exist
// at zero from boot.
func (m *Metrics) Prime() {
	m.Revealed.WithLabelValues("ok")
	m.Revealed.WithLabelValues("gone")
	for _, r := range []string{reasonTooLarge, reasonInvalid, reasonEmpty, reasonTTL, reasonMalformed} {
		m.Rejected.WithLabelValues(r)
	}
}
