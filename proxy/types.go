package proxy

import (
	"net"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type ProxyMode int

type Proxy struct {
	DisableConnect bool
	EgressAddress net.Addr
	ProxyMode ProxyMode
	OmitForwardedHeaders bool
	// Identifier for use in the Via header
	Identifier string
	cachedIdentifier string
	// Callbacks to allow consumers to veto requests
	RequestFilter func(request http.Request) bool
	TunnelFilter func(destination string) bool
	// Allow access to transport and dialer so that consumers can alter timeouts
	Transport *http.Transport
	Dialer *net.Dialer
}

type LeveledLogger struct {
	Logger *log.Logger
	Level log.Level
}