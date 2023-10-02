package main

import "errors"

var NilInvokeError = errors.New(
	"attempted to invoke function on a nil value")
var NilArgumentError = errors.New(
	"attempted to invoke function with a nil argument")

var NonResponseCachingError = errors.New(
	"attempted to cache a non-response dns.Msg")
var NonSuccessCachingError = errors.New(
	"attempted to cache a non-success dns.Msg")
var UnsupportedCachingError = errors.New(
	"attempted to cache an unsupported type of dns.Msg")
var InvalidQuestionError = errors.New(
	"abnormal number of questions in dns.Msg")
var InvalidAnswerError = errors.New(
	"abnormal number of answers in dns.Msg")
var ExpiredCacheError = errors.New(
	"the given cache entry has expired TTL")
var DomainBlockedError = errors.New(
	"the requested domain name is blocked")
