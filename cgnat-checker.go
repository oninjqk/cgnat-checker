package main

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
)

func isCGNATLocal(ip net.IP) bool {
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

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

func getPublicIPViaSTUN() (net.IP, error) {
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
	localIPs, err := getLocalIPs()
	if err != nil {
		fmt.Println("error retrieving local IPs:", err)
		return
	}
	
	var localCGNAT bool
	for _, ip := range localIPs {
		if isCGNATLocal(ip) {
			localCGNAT = true
			break
		}
	}

	pubIP, err := getPublicIPViaSTUN()
	if err != nil {
		fmt.Println("STUN error:", err)
		return
	}

	fmt.Println("Local CGNAT detected:", localCGNAT)
	fmt.Println("Public IP:", pubIP)

	if localCGNAT {
		fmt.Println("CGNAT confirmed")
	} else if !localCGNAT && !isCGNATLocal(pubIP) {
		fmt.Println("Likely common NAT or public IP")
	} else {
		fmt.Println("NAT detection inconclusive")
	}
}

