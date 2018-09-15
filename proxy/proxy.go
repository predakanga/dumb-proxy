package proxy

import (
	log "github.com/sirupsen/logrus"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
)

func (p *Proxy) InitializeTransport() {
	if p.Transport == nil {
		if p.Dialer == nil {
			p.Dialer = &net.Dialer {
				Timeout: DefaultConnectTimeout,
				LocalAddr: p.EgressAddress,
			}
		}
		p.Transport = &http.Transport {
			IdleConnTimeout: DefaultIdleConnectionTimeout,
			ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
			DialContext: p.Dialer.DialContext,
		}
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if p.Transport == nil {
		p.InitializeTransport()
	}

	if req.Method == "CONNECT" && p.ProxyMode != HttpProxy {
		if p.DisableConnect {
			defaultHttpError(w, http.StatusForbidden)
		} else {
			p.ServeTunnel(w, req)
		}
	} else {
		p.ServeProxy(w, req)
	}
}

func (p *Proxy) ServeProxy(w http.ResponseWriter, req *http.Request) {
	var (
		proxiedReq *http.Request
		err error
	)

	// Stat tracking
	currentRequests.Inc()
	defer currentRequests.Dec()

	// SearchStrings returns len(a) when the string isn't found
	if sort.SearchStrings(allowedMethods, req.Method) == len(allowedMethods) {
		defaultHttpError(w, http.StatusNotImplemented)
		return
	}

	proxiedUrl := *req.URL

	// Determine whether we can handle this kind of request
	// Transparent requests will have an empty host in their URL
	if proxiedUrl.Host == "" {
		if p.ProxyMode == HttpProxy {
			log.Debugf("Received transparent request while not in transparent mode: %v", req)
			defaultHttpError(w, http.StatusBadRequest)
			return
		}
		// In transparent mode, Host is in the Host header
		proxiedUrl.Host = req.Host
		// And scheme is in X-Scheme
		proxiedUrl.Scheme = req.Header.Get("X-Scheme")
		if proxiedUrl.Scheme == "" {
			proxiedUrl.Scheme = "http"
		}
	} else if p.ProxyMode == TransparentProxy {
		// Received an HTTP proxy request while in transparent-only mode
		log.Debugf("Received proxy request while not in proxy mode: %v", req)
		defaultHttpError(w, http.StatusBadRequest)
		return
	}

	if proxiedUrl.Scheme != "http" && proxiedUrl.Scheme != "https" {
		// Log - request received with invalid Scheme
		log.Debugf("Received request with invalid scheme: %v", proxiedUrl.Scheme)
		defaultHttpError(w, http.StatusBadRequest)
		return
	}

	// Avoid request loops using the Via header
	if p.Identifier == "" {
		// Generate a random string
		p.Identifier = randomString(16)
		p.cachedIdentifier = "1.1 " + p.Identifier
	}
	currentVia := req.Header.Get("Via")
	for _, viaSegment := range strings.Split(currentVia, ", ") {
		if viaSegment == p.Identifier {
			log.Warnf("Encountered looping request: %v", req)
			defaultHttpError(w, http.StatusLoopDetected)
			return
		}
	}

	// Create our new request - we only need the URL and headers
	if proxiedReq, err = http.NewRequest(req.Method, proxiedUrl.String(), req.Body); err != nil {
		log.Warnf("Failed to create new request: %v", err)
		defaultHttpError(w, http.StatusInternalServerError)
		return
	}
	proxiedReq.Header = req.Header

	// Set the ongoing Via header
	if currentVia == "" {
		proxiedReq.Header.Set("Via", p.cachedIdentifier)
	} else {
		proxiedReq.Header.Set("Via", currentVia + ", " + p.cachedIdentifier)
	}
	// Remove our custom headers
	proxiedReq.Header.Del("X-Scheme")
	// Wipe the hop-by-hop headers
	for _, key := range hopByHopHeaders {
		proxiedReq.Header.Del(key)
	}
	// And add our own forwarded headers if need be
	if !p.OmitForwardedHeaders {
		if host, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
			log.Errorf("Encountered a request with invalid RemoteAddr: %v", req.RemoteAddr)
			defaultHttpError(w, http.StatusInternalServerError)
			return
		} else {
			forwardedHost := req.Header.Get("X-Forwarded-Host")
			if forwardedHost == "" {
				proxiedReq.Header.Set("X-Forwarded-Host", host)
			} else {
				proxiedReq.Header.Set("X-Forwarded-Host", forwardedHost + ", " + host)
			}
		}
	}

	// Finally, check that we should send it
	if p.RequestFilter != nil && !p.RequestFilter(*proxiedReq) {
		defaultHttpError(w, http.StatusForbidden)
		return
	}

	// And make it so
	log.Infof("Retrieving %v for %v", proxiedUrl.String(), req.RemoteAddr)
	proxiedRequests.Inc()
	if resp, err := p.Transport.RoundTrip(proxiedReq); err != nil {
		log.Warnf("Failed to make request to %v: %v", proxiedUrl, err)
		defaultHttpError(w, http.StatusInternalServerError)
		return
	} else {
		// TODO: Check if we can just use Write
		//resp.Write(w)
		defer resp.Body.Close()
		// Headers have to be added before calling WriteHeader
		for headerName, headerValues := range resp.Header {
			for _, headerValue := range headerValues {
				w.Header().Add(headerName, headerValue)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

func (p *Proxy) ServeTunnel(w http.ResponseWriter, req *http.Request) {
	// Stat tracking
	currentTunnels.Inc()
	defer currentTunnels.Dec()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Warnf("Failed to hijack request: Hijack not supported (in %v)", req)
		defaultHttpError(w, http.StatusInternalServerError)
		return
	}

	// Make sure the request has a valid port
	dstAddr := req.RequestURI
	if _, _, err := net.SplitHostPort(dstAddr); err != nil {
		log.Warnf("Received a CONNECT request for an invalid address: %v", req)
		defaultHttpError(w, http.StatusInternalServerError)
		return
	}

	// Let the consumer veto the tunnel
	if p.TunnelFilter != nil && !p.TunnelFilter(dstAddr) {
		defaultHttpError(w, http.StatusForbidden)
		return
	}

	// Establish our connection before hijacking, so that go can send an error if need be
	dstConn, err := p.Transport.DialContext(req.Context(), "tcp", req.RequestURI)
	if err != nil {
		log.Warnf("Couldn't connect to %v while handling %v: %v", dstAddr, req, err)
		defaultHttpError(w, http.StatusServiceUnavailable)
		return
	}

	// Have to send an OK before starting the tunnel
	log.Infof("Tunneling %v for %v", dstAddr, req.RemoteAddr)
	tunneledRequests.Inc()
	w.WriteHeader(http.StatusOK)

	srcConn, pendingBuffer, err := hijacker.Hijack()
	if err != nil {
		log.Warnf("Failed to hijack request: %v (in %v)", err, req)
		defaultHttpError(w, http.StatusInternalServerError)
		return
	}

	go pipe(srcConn, dstConn, pendingBuffer)
	go pipe(dstConn, srcConn, nil)
}
