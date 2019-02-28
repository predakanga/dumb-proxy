package proxy

import "github.com/prometheus/client_golang/prometheus"

var (
	servedRequests = prometheus.NewCounterVec(prometheus.CounterOpts {
		Namespace: "proxy",
		Name: "served_requests_total",
		Help: "Number of served requests",
	}, []string{"type"})
	inflightRequests = prometheus.NewGaugeVec(prometheus.GaugeOpts {
		Namespace: "proxy",
		Name: "inflight_requests",
		Help: "Number of currently running requests",
	}, []string{"type"})
	dataTransferred = prometheus.NewCounterVec(prometheus.CounterOpts {
		Namespace: "proxy",
		Name: "transferred_bytes_total",
		Help: "Bytes transferred since the server started",
	}, []string{"type", "direction"})
)

func init() {
	prometheus.MustRegister(servedRequests, inflightRequests, dataTransferred)
}