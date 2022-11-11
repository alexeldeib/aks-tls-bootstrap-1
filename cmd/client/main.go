package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/Azure/aks-tls-bootstrap/pkg/client"
	"github.com/sirupsen/logrus"
)

var (
	log       = logrus.New()
	clientId  = flag.String("client-id", "", "The client ID for the assigned identity to use.")
	logFormat = flag.String("log-format", "json", "Log format: json or text, default: json")
	nextProto = flag.String("next-proto", "aks-tls-bootstrap", "ALPN Next Protocol value to send.")
	debug     = flag.Bool("debug", false, "enable debug logging (WILL LOG AUTHENTICATION DATA)")
)

func main() {
	flag.Parse()
	log.SetReportCaller(true)

	switch strings.ToLower(*logFormat) {
	case "text":
		log.SetFormatter(&logrus.TextFormatter{})
	default:
		log.SetFormatter(&logrus.JSONFormatter{})
	}

	if *debug {
		log.SetLevel(logrus.DebugLevel)
	}

	token, err := client.GetBootstrapToken(log, *clientId, *nextProto)
	if err != nil {
		log.Fatalf("Failed to retrieve bootstrap token: %v", err)
	}

	fmt.Println(token)
}
