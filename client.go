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
	qns    string
	tlsCfg *tls.Config
	client *dns.Client
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
	tlsCfg := tls.Config{}
	dc := new(dns.Client)
	dc.Net = cc.proto
	dc.SingleInflight = true
	tc := tlsClient{
		client: dc,
		qns:    cc.ns + ":" + strconv.Itoa(cc.port),
		tlsCfg: &tlsCfg,
	}
	return &tc
}

func (tc tlsClient) Exchange(req *dns.Msg) (*dns.Msg, error) {
	conn, err := dns.DialWithTLS("tcp-tls", tc.qns, tc.tlsCfg)
	if err != nil {
		return nil, err
	}
	resp, _, err := tc.client.ExchangeWithConn(req, conn)
	if err != nil {
		return nil, err
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
