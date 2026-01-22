package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func isGCNAT(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	n := ipToUint32(p)
	return n >= 0x64400000 && n <= 0x647FFFFF
}

func getExternalIP() (string, error) {
	r, e := http.Get("https://api.ipify.org")
	if e != nil {
		return "", e
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b), nil
}

func main() {
	ext, e := getExternalIP()
	if e != nil {
		fmt.Println("external error:", e)
		return
	}
	cgnat := "no"
	if isGCNAT(ext) {
		cgnat = "yes"
	}
	fmt.Printf("external ip: %s\nCGNAT: %s\n", ext, cgnat)
}
