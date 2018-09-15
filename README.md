# dumb-proxy
This is a very simple HTTP proxy written in Go.

It's main purpose is to allow nginx to access arbitrary websites with it's proxy_pass directive.

To that end, this proxy implements a non-standard transparent proxy mode, using the X-Scheme header to determine how to access the upstream server.
