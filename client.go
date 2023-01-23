package main

import (
	"context"
	"crypto/tls"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"strconv"
)

type DNSClient interface {
	Exchange(*dns.Msg) (*dns.Msg, error)
}

type tlsClient struct {
	client *dns.Client
	conn   *dns.Conn
	tlsCfg *tls.Config
	qns    string
	renew  chan struct{}
}

type clientConfig struct {
	ns    string
	port  int
	proto string
}

func NewDNSClient(cc *clientConfig) DNSClient {
	return NewTLSClient(cc)
}

func NewTLSClient(cc *clientConfig) *tlsClient {
	tlsCfg := &(tls.Config{})
	dc := new(dns.Client)
	dc.Net = cc.proto
	dc.SingleInflight = true
	tc := tlsClient{
		client: dc,
		conn:   nil,
		tlsCfg: tlsCfg,
		qns:    cc.ns + ":" + strconv.Itoa(cc.port),
		renew:  make(chan struct{}, 1),
	}
	tc.renew <- struct{}{}
	return &tc
}

func (tc *tlsClient) CreateConnection() error {
	conn, err := dns.DialWithTLS("tcp-tls", tc.qns, tc.tlsCfg)
	if err != nil {
		return err
	}
	tc.conn = conn
	return nil
}

func (tc *tlsClient) Lock() {
	<-tc.renew
}

func (tc *tlsClient) Unlock() {
	tc.renew <- struct{}{}
}

func (tc *tlsClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var resp *dns.Msg
	if tc.conn == nil {
		tc.Lock()
		// prevent race condition
		if tc.conn == nil {
			err = tc.CreateConnection()
			if err != nil {
				tc.Unlock()
				return nil, err
			}
		}
		tc.Unlock()
	}
	conn := tc.conn
	resp, _, err = tc.client.ExchangeWithConn(req, conn)
	if err != nil {
		tc.Lock()
		// prevent race condition
		if tc.conn == conn {
			tc.conn.Close()
			err = tc.CreateConnection()
			if err != nil {
				tc.Unlock()
				return nil, err
			}
		}
		tc.Unlock()
		resp, _, err = tc.client.ExchangeWithConn(req, tc.conn)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func NewHTTPSClient(resolverProto string, resolverIP string) *http.Client {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := tls.Dialer{}
				return d.DialContext(ctx, resolverProto, resolverIP)
			},
		},
	}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	http.DefaultTransport.(*http.Transport).DialContext = dialContext
	return &http.Client{}
}
