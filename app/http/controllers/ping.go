package controllers

import (
	"fmt"
	net "net/http"

	"github.com/confetti-framework/contract/inter"
	"github.com/confetti-framework/foundation/http/outcome"
)

// Ping is an endpoint with which you can check whether your application is responding.
func Ping(_ inter.Request) inter.Response {
	a := "dsasd"
	fmt.Println(a)

	return outcome.Html("pong").Status(net.StatusOK)
}
