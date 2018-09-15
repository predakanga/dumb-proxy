package proxy

import "github.com/prometheus/client_golang/prometheus"

var (
	proxiedRequests = prometheus.NewCounter(prometheus.CounterOpts {
		Name: "proxied_requests",
		Help: "Number of requests proxied",
	})
	tunneledRequests = prometheus.NewCounter(prometheus.CounterOpts {
		Name: "tunneled_requests",
		Help: "Number of tunnels created",
	})
	currentRequests = prometheus.NewGauge(prometheus.GaugeOpts {
		Name: "current_requests",
		Help: "Number of requests currently in flight",
	})
	currentTunnels = prometheus.NewGauge(prometheus.GaugeOpts {
		Name: "current_tunnels",
		Help: "Number of tunnels currently open",
	})
)

func init() {
	prometheus.MustRegister(proxiedRequests, tunneledRequests, currentRequests, currentTunnels)
}