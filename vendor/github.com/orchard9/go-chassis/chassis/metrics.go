package chassis

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// metrics holds the RED HTTP collectors on a private registry (no global state,
// so tests and multiple apps never collide). The route label is the matched
// ServeMux pattern — bounded cardinality, never the raw path.
type metrics struct {
	reg      *prometheus.Registry
	reqs     *prometheus.CounterVec
	dur      *prometheus.HistogramVec
	inflight prometheus.Gauge
}

// newMetrics builds the RED collectors and registers them alongside any
// service-owned collectors (Config.Collectors) on the same private registry —
// so /metrics is one scrape and a domain gauge cannot be lost to a second
// endpoint nobody remembers to scrape.
func newMetrics(service string, extra ...prometheus.Collector) *metrics {
	reg := prometheus.NewRegistry()
	labels := prometheus.Labels{"service": service}
	m := &metrics{
		reg: reg,
		reqs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total", Help: "Total HTTP requests.", ConstLabels: labels,
		}, []string{"method", "route", "status"}),
		dur: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_request_duration_seconds", Help: "HTTP request latency.",
			Buckets: prometheus.DefBuckets, ConstLabels: labels,
		}, []string{"method", "route"}),
		inflight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "http_requests_in_flight", Help: "In-flight HTTP requests.", ConstLabels: labels,
		}),
	}
	reg.MustRegister(m.reqs, m.dur, m.inflight,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	for _, c := range extra {
		reg.MustRegister(c)
	}
	return m
}

func (m *metrics) observe(method, route string, status int, d time.Duration) {
	m.countOnly(method, route, status)
	m.dur.WithLabelValues(method, route).Observe(d.Seconds())
}

// countOnly records a request without timing it. For responses whose elapsed
// time is not a latency — an event stream ends when the operator closes the
// tab, and putting that in the histogram makes every latency alert lie.
func (m *metrics) countOnly(method, route string, status int) {
	m.reqs.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
}

// handler serves the Prometheus exposition for the metrics agent to scrape.
func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}
