package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	// Parse command-line flags
	debugFlag := flag.Bool("debug", false, "Print debug information")
	flag.Parse()

	// Get the hostname and port from the command-line arguments
	hostname, port := parseHostnameAndPort(flag.Args())

	// Connect to the remote host
	conn, err := tls.Dial("tcp", hostname+":"+port, &tls.Config{
		InsecureSkipVerify: false,
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

	// Print debug information if --debug flag is set
	if *debugFlag {
		fmt.Println("Certificate expiration date:", expirationDate)
		fmt.Printf("Certificate subject: %s\nCommon Name (CN): %s\n", certs[0].Subject, certs[0].Subject.CommonName)
	}

	// Calculate the number of days until the certificate expires
	daysLeft := int(time.Until(expirationDate).Truncate(24*time.Hour).Hours() / 24)

	fmt.Printf("Days left until the certificate expires: %d\n", daysLeft)
}

func parseHostnameAndPort(args []string) (string, string) {
	var hostname, port string

	if len(args) == 0 {
		fmt.Println("Usage: go run main.go <hostname> [port] [--debug]")
		os.Exit(1)
	}

	if strings.HasPrefix(args[0], "https://") {
		u, err := url.Parse(args[0])
		if err != nil {
			fmt.Printf("Error parsing hostname: %v\n", err)
			os.Exit(1)
		}
		hostname = u.Hostname()
		port = u.Port()
	} else {
		hostname = args[0]
	}

	if len(args) > 1 {
		port = args[1]
	}

	if port == "" {
		port = "443" // Default to port 443 if not provided
	}

	return hostname, port
}
