package http

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

type Proxy struct {
	port   string
	logger *logrus.Logger
}

func NewProxy(port string, logger *logrus.Logger) *Proxy {
	return &Proxy{
		port:   port,
		logger: logger,
	}
}

func (p *Proxy) Start() error {
	server := &http.Server{
		Addr:    ":" + p.port,
		Handler: http.HandlerFunc(p.handleRequest),
	}
	
	p.logger.Infof("HTTP proxy listening on port %s", p.port)
	return server.ListenAndServe()
}

func (p *Proxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	go io.Copy(destConn, clientConn)
	io.Copy(clientConn, destConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Scheme, "http") {
		r.URL.Scheme = "http"
	}

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}