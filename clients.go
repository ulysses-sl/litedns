package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	DefaultProto = "default"
	UDPProto     = "udp"
	TCPProto     = "tcp"
	TLSProto     = "tcp-tls"
)
const TCPTimeoutMillis = 1000
const TCPBackOffMillis = 10
const TCPMaxRetry = 3

type DNSClient interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
}

type UDPClient struct {
	client     *dns.Client
	serverAddr string
}

type TCPClient struct {
	client     *dns.Client
	conn       *dns.Conn
	tlsCfg     *tls.Config
	serverAddr string
	sync.Mutex
}

type DefaultClient struct {
	udpClient DNSClient
	tcpClient DNSClient
}

// DNSClientPool represents a pool of clients, each querying a different
// upstream DNS server.
type DNSClientPool struct {
	clients []DNSClient
	C       <-chan DNSClient
}

// NewDNSClientPool creates a pool of clients
func NewDNSClientPool(servers []*ServerConfig) *DNSClientPool {
	pool := make(chan DNSClient, 0)
	cp := &DNSClientPool{
		C: pool,
	}
	if len(servers) == 0 {
		close(pool)
		return cp
	}
	cp.clients = make([]DNSClient, len(servers))
	for i := 0; i < len(servers); i++ {
		cp.clients[i] = NewDNSClient(servers[i])
	}
	go func() {
		i := 0
		for {
			if i >= len(cp.clients) {
				i = 0
			}
			pool <- cp.clients[i]
			i += 1
		}
	}()
	return cp
}

func NewDNSClient(server *ServerConfig) DNSClient {
	if server == nil {
		return (*DefaultClient)(nil)
	}
	var rv DNSClient
	switch server.Proto {
	case DefaultProto:
		rv = NewDefaultClient(server.String())
	case UDPProto:
		rv = NewUDPClient(server.String())
	case TCPProto:
		rv = NewTCPClient(server.String(), false)
	case TLSProto:
		rv = NewTCPClient(server.String(), true)
	default:
		log.Panicf("invalid protocol %s; this should not happen", server.Proto)
	}
	return rv
}

func NewDefaultClient(serverAddr string) DNSClient {
	uc := NewUDPClient(serverAddr)
	tc := NewTCPClient(serverAddr, false)
	return &DefaultClient{
		udpClient: uc,
		tcpClient: tc,
	}
}

func NewUDPClient(serverAddr string) DNSClient {
	return &UDPClient{
		client:     new(dns.Client),
		serverAddr: serverAddr,
	}
}

func NewTCPClient(serverAddr string, useTLS bool) DNSClient {
	dc := new(dns.Client)
	dc.Net = TCPProto
	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg = &(tls.Config{})
	}
	tc := TCPClient{
		client:     dc,
		conn:       nil,
		tlsCfg:     tlsCfg,
		serverAddr: serverAddr,
	}
	return &tc
}

func (c *DefaultClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if c == nil {
		return nil, fmt.Errorf(
			"attempted to use uninitialized DNS client")
	}
	resp, err := c.udpClient.Exchange(msg)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		return c.tcpClient.Exchange(msg)
	}
	return resp, nil
}

func (c *UDPClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	if c == nil {
		return nil, fmt.Errorf(
			"attempted to use uninitialized DNS client")
	}
	resp, _, err := c.client.Exchange(msg, c.serverAddr)
	return resp, err
}

func (tc *TCPClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
	if tc == nil {
		return nil, fmt.Errorf(
			"attempted to use uninitialized DNS client")
	}
	var resp *dns.Msg
	var err error
	tc.Lock()
	defer tc.Unlock()
	if tc.conn == nil {
		tc.conn, err = tc.CreateConn()
		if err != nil {
			return nil, err
		}
	}
	resp, _, err = tc.client.ExchangeWithConn(req, tc.conn)
	// retry with new connection if connection closed
	if err == nil && resp != nil {
		return resp, nil
	}
	backoff := time.Duration(TCPBackOffMillis) * time.Millisecond
	for i := 0; i < TCPMaxRetry; i++ {
		_ = tc.conn.Close()
		tc.conn = nil
		time.Sleep(backoff)
		backoff *= 2
		tc.conn, err = tc.CreateConn()
		if err != nil {
			return nil, err
		}
		resp, _, err = tc.client.ExchangeWithConn(req, tc.conn)
		if err == nil && resp != nil {
			return resp, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("connection failed")
	}
	return resp, nil
}

func (tc *TCPClient) GetOrCreateConn() (*dns.Conn, error) {
	tc.Lock()
	defer tc.Unlock()
	if tc.conn != nil {
		if IsConnAlive(tc.conn) {
			return tc.conn, nil
		}
		_ = tc.conn.Close()
		tc.conn = nil
	}
	conn, err := tc.CreateConn()
	if err != nil {
		return nil, err
	}
	tc.conn = conn
	return tc.conn, nil
}

func (tc *TCPClient) CreateConn() (*dns.Conn, error) {
	timeout := TCPTimeoutMillis * time.Millisecond
	if tc.tlsCfg != nil {
		return dns.DialTimeoutWithTLS("tcp-tls", tc.serverAddr,
			tc.tlsCfg, timeout)
	}
	return dns.DialTimeout("tcp", tc.serverAddr, timeout)
}

// IsConnAlive checks if a TCP connection is kept alive.
func IsConnAlive(conn *dns.Conn) bool {
	if conn == nil {
		return false
	}
	oneByte := make([]byte, 1)
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		return false
	}
	if _, err := conn.Read(oneByte); err == io.EOF {
		return false
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return false
	}
	return true
}

func NewHTTPSClient(resolverIP string) *http.Client {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := tls.Dialer{}
				return d.DialContext(ctx, TCPProto, resolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialContext
	client := &http.Client{
		Transport: transport,
	}
	return client
}
