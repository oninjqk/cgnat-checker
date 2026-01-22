/*
I decided to improve the reliability of the code, as the previous approach,
which only compared the IP with the provider RFC 6598 range (100.64.0.0/10),
did not cover all possible CGNAT scenarios.

The new approach:
1. Checks local interface IPs for 100.64.0.0/10 (CGNAT range)
2. Uses STUN to discover the public IP, allowing NAT detection even behind multiple layers
3. Combines local and public IPs to reliably confirm CGNAT or common NAT
*/

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

// isCGNATLocal checks if the given IP is in the CGNAT private range 100.64.0.0/10
func isCGNATLocal(ip net.IP) bool {
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10") // continue checking 100.64.0.0/10, equivalent to previous 0x64400000-0x647FFFFF
	return cgnat.Contains(ip)
}

// getLocalIPs returns all IPv4 addresses of the current host interfaces
func getLocalIPs() ([]net.IP, error) {
	var ips []net.IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// getPublicIPViaSTUN performs a STUN BindingRequest to discover the public IP
// This is critical to detect NAT even behind multiple layers (e.g., CGNAT + home NAT)
func getPublicIPViaSTUN() (net.IP, error) {
	// use UDP to connect to a public STUN server
	c, err := net.DialTimeout("udp", "stun.l.google.com:19302", 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	client, err := stun.NewClient(c)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var publicIP net.IP
	err = client.Do(stun.MustBuild(stun.TransactionID, stun.BindingRequest), func(res stun.Event) {
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err == nil {
			publicIP = xorAddr.IP
		}
	})
	if err != nil {
		return nil, err
	}
	return publicIP, nil
}

func main() {
	// get all local IP addresses
	localIPs, err := getLocalIPs()
	if err != nil {
		fmt.Println("error retrieving local IPs:", err)
		return
	}

	// detect if any local IP is in CGNAT range
	var localCGNAT bool
	for _, ip := range localIPs {
		if isCGNATLocal(ip) {
			localCGNAT = true
			break
		}
	}

	// discover public IP via STUN
	pubIP, err := getPublicIPViaSTUN()
	if err != nil {
		fmt.Println("STUN error:", err)
		return
	}

	fmt.Println("Local CGNAT detected:", localCGNAT)
	fmt.Println("Public IP:", pubIP)

	// combine local and public IP info for final CGNAT detection
	if localCGNAT {
		fmt.Println("CGNAT confirmed")
	} else if !localCGNAT && !isCGNATLocal(pubIP) {
		fmt.Println("Likely common NAT or public IP")
	} else {
		fmt.Println("NAT detection inconclusive")
	}
}
