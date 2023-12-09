// fw-test-agent is a tool (operating as a CLI or daemon) that runs
// on hosts behind a firewall and reports their public IP address(s)
// and DNS state and interface properties and ability to reach
// things on the network. It's meant to be part of a larger system
// to check firewall rules & network configuration. (Checking that
// the host's DHCP and IPv6 autoconfig and iptables etc are working for
// VMs running on that host)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
	"unicode"
)

type Result interface {
	String() string
}

var flagJSON = flag.Bool("json", false, "output JSON instead of text")

func main() {
	flag.Parse()
	var sawErr bool
	errf := func(format string, args ...any) {
		sawErr = true
		log.SetFlags(0)
		log.Printf(format, args...)
	}
	out := func(cmd string, res Result, err error) {
		if err != nil {
			errf("%s: %v", cmd, err)
			return
		}
		if *flagJSON {
			j, err := json.Marshal(res)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s\n", j)
		} else {
			fmt.Printf("%s: %s\n", cmd, res)
		}
	}

	for _, cmd := range flag.Args() {
		switch {
		case cmd == "v6":
			addr, err := getPublicIPv6()
			out(cmd, addr, err)
		case cmd == "v4":
			addr, err := getPublicIPv4()
			out(cmd, addr, err)
		case cmd == "dns" || strings.HasPrefix(cmd, "dns:"):
			// dns
			// dns:google.com
			_, host, _ := strings.Cut(cmd, ":")
			if host == "" {
				host = "google.com"
				cmd = "dns:google.com"
			}
			res, err := checkDNS(host)
			out(cmd, res, err)
		default:
			errf("unknown command: %s", cmd)
		}
	}
	if sawErr {
		os.Exit(1)
	}
}

type AddrResult struct {
	Addr netip.Addr
}

func (r *AddrResult) String() string {
	return r.Addr.String()
}

func getPublicIPv6() (*AddrResult, error) {
	return canHazIP(true)
}

func getPublicIPv4() (*AddrResult, error) {
	return canHazIP(false)
}

func canHazIP(v6 bool) (*AddrResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	googDNS := "8.8.8.8"
	if v6 {
		googDNS = "2001:4860:4860::8888"
	}
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort(googDNS, "53"))
		},
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if !strings.ContainsFunc(network, unicode.IsDigit) {
					if v6 {
						network += "6"
					} else {
						network += "4"
					}
				}
				var d net.Dialer
				d.Resolver = res
				return d.DialContext(ctx, network, address)
			},
		},
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://canhazip.com/", nil)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("canhazip.com returned non-200 status code: %v", resp.Status)
	}
	all, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	a, err := netip.ParseAddr(strings.TrimSpace(string(all)))
	if err != nil {
		return nil, err
	}
	return &AddrResult{Addr: a}, nil
}

type DNSResult struct {
	Addrs []netip.Addr
}

func (r *DNSResult) String() string {
	var sb strings.Builder
	for i, a := range r.Addrs {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(a.String())
	}
	return sb.String()
}

func checkDNS(host string) (*DNSResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var res net.Resolver
	addrs, err := res.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	ret := &DNSResult{}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, fmt.Errorf("invalid resolved address %q", a)
		}
		ret.Addrs = append(ret.Addrs, ip)
	}
	return ret, nil
}
