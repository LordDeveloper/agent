package ppforward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

type Server struct {
	cfg    Config
	logger *log.Logger
	mu     sync.Mutex
	ln     []net.Listener
	wg     sync.WaitGroup
}

func NewServer(cfg Config, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(os.Stderr, "pp-forward ", log.LstdFlags)
	}
	return &Server{cfg: cfg, logger: logger}
}

func (s *Server) Run(ctx context.Context) error {
	if len(s.cfg.Rules) == 0 {
		s.logger.Println("no rules configured; idle")
		<-ctx.Done()
		return ctx.Err()
	}

	listeners := make([]net.Listener, 0, len(s.cfg.Rules))
	for _, rule := range s.cfg.Rules {
		ln, err := net.Listen("tcp", rule.Listen)
		if err != nil {
			for _, existing := range listeners {
				_ = existing.Close()
			}
			return fmt.Errorf("listen %s (%s): %w", rule.Listen, rule.Tag, err)
		}
		listeners = append(listeners, ln)
		tag := rule.Tag
		target := rule.Target
		s.logger.Printf("listening %s -> %s tag=%s", rule.Listen, target, tag)
		s.wg.Add(1)
		go func(listener net.Listener, targetAddr, inboundTag string) {
			defer s.wg.Done()
			s.acceptLoop(ctx, listener, targetAddr, inboundTag)
		}(ln, target, tag)
	}

	s.mu.Lock()
	s.ln = listeners
	s.mu.Unlock()

	<-ctx.Done()

	s.mu.Lock()
	for _, ln := range s.ln {
		_ = ln.Close()
	}
	s.ln = nil
	s.mu.Unlock()

	s.wg.Wait()
	return ctx.Err()
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, targetAddr, tag string) {
	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Printf("accept failed listen=%s tag=%s: %v", ln.Addr(), tag, err)
			continue
		}

		s.wg.Add(1)
		go func(clientConn net.Conn) {
			defer s.wg.Done()
			s.handleConn(clientConn, targetAddr, tag)
		}(client)
	}
}

func (s *Server) handleConn(client net.Conn, targetAddr, tag string) {
	defer client.Close()

	clientTCP, ok := client.RemoteAddr().(*net.TCPAddr)
	if !ok {
		s.logger.Printf("skip non-tcp client tag=%s remote=%s", tag, client.RemoteAddr())
		return
	}
	if clientTCP.IP.To4() == nil {
		s.logger.Printf("skip non-ipv4 client tag=%s remote=%s", tag, client.RemoteAddr())
		return
	}

	localTCP, ok := client.LocalAddr().(*net.TCPAddr)
	if !ok {
		s.logger.Printf("skip invalid local addr tag=%s", tag)
		return
	}

	upstream, err := net.Dial("tcp", targetAddr)
	if err != nil {
		s.logger.Printf("dial target failed tag=%s target=%s: %v", tag, targetAddr, err)
		return
	}
	defer upstream.Close()

	header, err := FormatProxyHeaderV1(clientTCP, localTCP)
	if err != nil {
		s.logger.Printf("proxy header failed tag=%s: %v", tag, err)
		return
	}
	if _, err := upstream.Write(header); err != nil {
		s.logger.Printf("write proxy header failed tag=%s: %v", tag, err)
		return
	}

	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errCh <- err }()
	go func() { _, err := io.Copy(client, upstream); errCh <- err }()
	<-errCh
}
