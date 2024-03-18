package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	hostname := flag.String("hostname", "", "Hostname to connect to")
	port := flag.String("port", "443", "Port to connect to (default 443)")
	flag.Parse()

	// Validate that the hostname argument is provided
	if *hostname == "" {
		fmt.Println("Error: hostname is required")
		flag.Usage()
		os.Exit(1)
	}

	// Connect to the remote host
	conn, err := tls.Dial("tcp", *hostname+":"+*port, nil)
	if err != nil {
		fmt.Println("Error connecting to host:", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Verify certificates
	certs := conn.ConnectionState().PeerCertificates
	opts := x509.VerifyOptions{
		CurrentTime: time.Now(),
	}
	_, err = certs[0].Verify(opts)
	if err != nil {
		fmt.Println("Certificate verification error:", err)
		os.Exit(1)
	}

	// Calculate expiration and days left
	// Ensure we drop all remaining hours and just displays the days
	expirationDate := certs[0].NotAfter
	daysLeft := int(time.Until(expirationDate).Truncate(24*time.Hour).Hours() / 24)

	fmt.Println("Days until certificate expiration:", daysLeft)
}
