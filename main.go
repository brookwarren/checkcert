package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	var hostname string
	port := "443"
	debugFlag := false

	if len(os.Args) > 1 {
		hostname = os.Args[1]
	}

	// Process argumentsswitch
	switch len(os.Args) {
	case 1: // this means NO args were provided
		fmt.Println("Usage: checkcert <hostname> [<port>] [--debug]")
		fmt.Println("- Defaults to 443 if port not specified.")
		fmt.Println("- The --debug option will print the CN, SANs, and the Expiration date.")
		os.Exit(0)
	case 2:
	case 3: // this means 2 args were provided
		if os.Args[2] == "--debug" {
			debugFlag = true
		} else {
			port = os.Args[2]
		}
	default:
		port = os.Args[2]
		if os.Args[3] == "--debug" {
			debugFlag = true
		}
	}

	// trim https:// if it is there
	hostname = strings.TrimPrefix(hostname, "http://")

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
	if debugFlag {
		fmt.Println("Certificate expiration date:", expirationDate)
		fmt.Printf("Certificate subject: %s\nCommon Name (CN): %s\n", certs[0].Subject, certs[0].Subject.CommonName)
		// Print Subject Alternative Names
		fmt.Println("Subject Alternative Names (SANs):")
		if len(certs[0].DNSNames) == 0 {
			fmt.Println("   None")
		} else {
			for _, san := range certs[0].DNSNames {
				fmt.Println("   ", san)
			}
		}
	}

	// Calculate the number of days until the certificate expires
	daysLeft := int(time.Until(expirationDate).Truncate(24*time.Hour).Hours() / 24)

	if debugFlag {
		fmt.Printf("Days left until the certificate expires: %d\n", daysLeft)
	} else {
		fmt.Printf("%d", daysLeft)
	}
}
