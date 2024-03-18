package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

func main() {
	// Check if the required command-line arguments are provided
	if len(os.Args) != 3 {
		fmt.Println("Usage: go run main.go <hostname> <port>")
		os.Exit(1)
	}

	hostname := os.Args[1]
	port := os.Args[2]

	// Connect to the remote host
	conn, err := tls.Dial("tcp", hostname+":"+port, &tls.Config{
		InsecureSkipVerify: false, // Set to true to skip certificate validation
	})
	if err != nil {
		fmt.Printf("Error connecting to %s:%s: %v\n", hostname, port, err)
		os.Exit(1)
	}
	defer conn.Close()

	// Get the server's certificate chain
	certs := conn.ConnectionState().PeerCertificates

	// Validate the certificate chain
	opts := x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}

	for _, cert := range certs[1:] {
		opts.Roots.AddCert(cert)
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		fmt.Printf("Error validating certificate chain: %v\n", err)
		os.Exit(1)
	}

	// Get the expiration date of the server's certificate
	expirationDate := certs[0].NotAfter

	// Calculate the number of days until the certificate expires
	daysLeft := int(time.Until(expirationDate).Truncate(24*time.Hour).Hours() / 24)

	fmt.Printf("Days left until the certificate expires: %d\n", daysLeft)
}
