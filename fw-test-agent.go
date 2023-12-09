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
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/bradfitz/fw-test-agent/systemdsvc"
	"tailscale.com/client/tailscale"
)

type Result interface {
	String() string
}

var (
	flagJSON      = flag.Bool("json", false, "output JSON instead of text")
	flagListen    = flag.String("listen", "", "listen address for HTTP server (e.g. \":8080\")")
	flagTailscale = flag.Bool("require-tailscale", false, "only serve connections from Tailscale")
	flagSystemd   = flag.String("systemd", "", "systemd action to perform. supported: install, uninstall")
)

func main() {
	flag.Parse()
	if *flagSystemd != "" {
		systemdsvc.HandleAction(*flagSystemd, "fw-test-agent.service", flag.Args()...)
		return
	}

	if *flagListen != "" {
		if flag.NArg() > 0 {
			log.Fatal("cannot specify both --listen and commands")
		}
		log.Fatal(http.ListenAndServe(*flagListen, http.HandlerFunc(serve)))
	}
	if *flagListen == "" && flag.NArg() == 0 {
		log.Fatal("must specify either --listen or commands")
	}

	var sawErr bool
	ctx := context.Background()
	errf := func(format string, args ...any) {
		sawErr = true
		log.SetFlags(0)
		log.Printf(format, args...)
	}
	onResult := func(cmd string, res Result, err error) {
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
		runCmd(ctx, cmd, onResult)
	}
	if sawErr {
		os.Exit(1)
	}
}

func runCmd(ctx context.Context, cmd string, onResult func(cmd string, res Result, err error)) {
	switch {
	case cmd == "v6":
		addr, err := getPublicIPv6(ctx)
		onResult(cmd, addr, err)
	case cmd == "v4":
		addr, err := getPublicIPv4(ctx)
		onResult(cmd, addr, err)
	case cmd == "dns" || strings.HasPrefix(cmd, "dns:"):
		// dns
		// dns:google.com
		_, host, _ := strings.Cut(cmd, ":")
		if host == "" {
			host = "google.com"
			cmd = "dns:google.com"
		}
		res, err := checkDNS(ctx, host)
		onResult(cmd, res, err)
	case strings.HasPrefix(cmd, "ping:"):
		_, host, _ := strings.Cut(cmd, ":")
		res, err := checkPing(ctx, host)
		onResult(cmd, res, err)
	case strings.HasPrefix(cmd, "tcp:"):
		_, hostport, _ := strings.Cut(cmd, ":")
		res, err := checkTCP(ctx, hostport)
		onResult(cmd, res, err)
	default:
		onResult(cmd, nil, fmt.Errorf("unknown command %q", cmd))
	}
}

func serve(w http.ResponseWriter, r *http.Request) {
	if *flagTailscale {
		who, err := tailscale.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			log.Printf("non-Tailscale access from %v: %v", r.RemoteAddr, err)
			http.Error(w, "only access over Tailscale permitted", http.StatusForbidden)
			return
		}
		log.Printf("got query from %v (%v)", r.RemoteAddr, who.UserProfile.DisplayName)
	}
	cmd := r.RequestURI[1:]
	if cmd == "" {
		io.WriteString(w, "fw-test-agent\n")
		return
	}
	type resT struct {
		Cmd    string
		Result any    `json:",omitempty"`
		Error  string `json:",omitempty"`
	}
	w.Header().Set("Content-Type", "application/json")
	for _, cmd := range strings.Split(cmd, ",") {
		runCmd(r.Context(), cmd, func(cmd string, res Result, err error) {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "\t")
			if err != nil {
				enc.Encode(resT{Cmd: cmd, Error: err.Error()})
			} else {
				enc.Encode(resT{Cmd: cmd, Result: res})
			}
		})
	}
}

type AddrResult struct {
	Addr netip.Addr
}

func (r *AddrResult) String() string {
	return r.Addr.String()
}

func getPublicIPv6(ctx context.Context) (*AddrResult, error) {
	return canHazIP(ctx, true)
}

func getPublicIPv4(ctx context.Context) (*AddrResult, error) {
	return canHazIP(ctx, false)
}

func canHazIP(ctx context.Context, v6 bool) (*AddrResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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
			DisableKeepAlives: true,
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

func checkDNS(ctx context.Context, host string) (*DNSResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
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

type PingResult struct {
	Success bool
}

func (r *PingResult) String() string {
	if r.Success {
		return "success"
	}
	return "failure"
}

func checkPing(ctx context.Context, host string) (*PingResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var timeoutFlag string
	switch runtime.GOOS {
	case "linux":
		timeoutFlag = "-W"
	case "darwin":
		timeoutFlag = "-t"
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	out, err := exec.CommandContext(ctx, "ping",
		"-c", "1",
		timeoutFlag, "4",
		host,
	).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ping failure: %v: %s", err, out)
	}
	return &PingResult{Success: true}, nil
}

type TCPResult struct {
	Success bool
}

func (r *TCPResult) String() string {
	if r.Success {
		return "success"
	}
	return "failure"
}

func checkTCP(ctx context.Context, hostport string) (*TCPResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	c.Close()
	return &TCPResult{Success: true}, nil
}
