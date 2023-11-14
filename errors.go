package main

import (
	"errors"
	"fmt"
)

var NilArgumentError = errors.New(
	"attempted to invoke function with a nil argument")
var NonResponseCachingError = errors.New(
	"attempted to cache a non-response dns.Msg")
var UnsupportedCachingError = errors.New(
	"attempted to cache an unsupported type of dns.Msg")
var InvalidQuestionError = errors.New(
	"abnormal number of questions in dns.Msg")
var ExpiredCacheError = errors.New(
	"the given cache entry has expired TTL")
var DomainBlockedError = errors.New(
	"the requested domain name is blocked")
var InvalidDomainNameError = errors.New(
	"invalid domain name provided")

func NewABPSyntaxError(lineNum int, lineStr string) error {
	return fmt.Errorf("invalid abp syntax at line %d: %s", lineNum, lineStr)
}

func NewInvalidDomainNameError(dn string) error {
	return fmt.Errorf("%w: %s", InvalidDomainNameError, dn)
}

func NewHTTPFailureError(method string, url string, statusCode int) error {
	return fmt.Errorf(
		"invalid HTTP status code on %s [%s]: %d",
		method, url, statusCode,
	)
}
