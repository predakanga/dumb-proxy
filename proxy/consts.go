package proxy

import "time"

// Defaults for the transport
const (
	DefaultConnectTimeout = 30*time.Second
	DefaultIdleConnectionTimeout = 30*time.Second
	DefaultResponseHeaderTimeout = 30*time.Second
)

// Enum describing the operation mode
const (
	HttpProxy ProxyMode = iota
	TransparentProxy
	HttpAndTransparentProxy
)

// For now we only want to support HEAD, GET, POST, OPTIONS and CONNECT
var allowedMethods = []string {
	"GET",
	"HEAD",
	"OPTIONS",
	"POST",
}

// As per https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hbh
var hopByHopHeaders = [...]string {
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}
