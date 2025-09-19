package socks5

import (
	"net"

	"github.com/armon/go-socks5"
	"github.com/sirupsen/logrus"
)

type Server struct {
	port   string
	logger *logrus.Logger
	server *socks5.Server
}

func NewServer(port string, logger *logrus.Logger) *Server {
	conf := &socks5.Config{}
	server, _ := socks5.New(conf)
	
	return &Server{
		port:   port,
		logger: logger,
		server: server,
	}
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		s.logger.Errorf("Failed to start SOCKS5 server: %v", err)
		return err
	}
	
	s.logger.Infof("SOCKS5 server listening on port %s", s.port)
	return s.server.Serve(listener)
}