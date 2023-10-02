package client

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/miekg/dns"
	"litedns/config"
	"log"
	"net"
	"net/http"
	"time"
)

const TCPTimeoutMillis = 1000

type DNSClientPool struct {
	clients []DNSClient
	C       <-chan DNSClient
}

func NewDNSClientPool(servers []*config.ServerConfig) *DNSClientPool {
	pool := make(chan DNSClient, 0)
	cp := &DNSClientPool{
		clients: make([]DNSClient, len(servers)),
		C:       pool,
	}
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

type DNSClient interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
}

func NewDNSClient(server *config.ServerConfig) DNSClient {
	var rv DNSClient
	switch server.Proto {
	case config.UDPProto:
		rv = NewUDPClient(server.String())
	case config.TCPProto:
		rv = NewTCPClient(server.String(), false)
	case config.TLSProto:
		rv = NewTCPClient(server.String(), true)
	default:
		log.Panicf("invalid protocol %s; this should not happen", server.Proto)
	}
	return rv
}

type UDPClient struct {
	client     *dns.Client
	serverAddr string
}

func NewUDPClient(serverAddr string) DNSClient {
	return &UDPClient{
		client:     new(dns.Client),
		serverAddr: serverAddr,
	}
}

func (c *UDPClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	resp, _, err := c.client.Exchange(msg, c.serverAddr)
	return resp, err
}

type TCPClient struct {
	client     *dns.Client
	conn       *dns.Conn
	tlsCfg     *tls.Config
	connLock   chan struct{}
	serverAddr string
}

func NewTCPClient(serverAddr string, useTLS bool) DNSClient {
	dc := new(dns.Client)
	dc.Net = config.TCPProto
	dc.SingleInflight = true
	var tlsCfg *tls.Config
	if useTLS {
		tlsCfg = &(tls.Config{})
	}
	tc := TCPClient{
		client:     dc,
		conn:       nil,
		tlsCfg:     tlsCfg,
		connLock:   make(chan struct{}, 1),
		serverAddr: serverAddr,
	}
	tc.connLock <- struct{}{}
	return &tc
}

func (tc *TCPClient) Lock() {
	<-tc.connLock
}

func (tc *TCPClient) Unlock() {
	tc.connLock <- struct{}{}
}

func (tc *TCPClient) CreateConn() error {
	if tc.conn != nil {
		return errors.New("connection already exists")
	}
	var conn *dns.Conn
	var err error
	if tc.tlsCfg != nil {
		conn, err = dns.DialTimeoutWithTLS(config.TLSProto, tc.serverAddr,
			tc.tlsCfg, TCPTimeoutMillis*time.Millisecond)
	} else {
		conn, err = dns.DialTimeout(config.TCPProto, tc.serverAddr,
			TCPTimeoutMillis*time.Millisecond)
	}
	if err != nil {
		return err
	}
	tc.conn = conn
	return nil
}

func (tc *TCPClient) GetConn() (*dns.Conn, error) {
	tc.Lock()
	defer tc.Unlock()
	if tc.conn != nil {
		return tc.conn, nil
	}
	// prevent race condition
	if tc.conn != nil {
		return tc.conn, nil
	}
	if err := tc.CreateConn(); err != nil {
		return nil, err
	}
	return tc.conn, nil
}

func (tc *TCPClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg
	conn, err := tc.GetConn()
	if err != nil {
		log.Panicf("cannot create TCP connection to %s: %s",
			tc.serverAddr, err.Error())
	}
	resp, _, err = tc.client.ExchangeWithConn(req, conn)
	if err == nil {
		return resp, nil
	}
	tc.Lock()
	// prevent race condition
	if tc.conn != conn {
		tc.Unlock() /* Race condition: already renewed. */
	} else {
		defer tc.Unlock() /* Defer until the successful exchange */
		err = tc.conn.Close()
		if err != nil {
			log.Panicf("cannot close TCP connection to %s: %s",
				tc.serverAddr, err.Error())
		}
		tc.conn = nil
		err = tc.CreateConn()
		if err != nil {
			log.Panicf("cannot renew TCP connection to %s: %s",
				tc.serverAddr, err.Error())
		}
	}
	resp, _, err = tc.client.ExchangeWithConn(req, tc.conn)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func NewHTTPSClient(resolverIP string) *http.Client {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := tls.Dialer{}
				return d.DialContext(ctx, config.TCPProto, resolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext
	return &http.Client{}
}
