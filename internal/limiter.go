package internal

import (
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/time/rate"
	"gopkg.in/mcuadros/go-syslog.v2"
)

var (
	ip6Regexp = regexp.MustCompile(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)
	ip4Regexp = regexp.MustCompile(`((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
)

type ReqLimiter struct {
	limiterMap     map[string]*rate.Limiter
	r              rate.Limit
	b              int
	addr           string
	onlyUnixSocket bool
	ipt            *iptables.IPTables
	ip6t           *iptables.IPTables
	ports          string
}

func NewReqLimiter(addr string, onlyUnixSocket bool, r float64, b int, ports string) *ReqLimiter {
	rl := &ReqLimiter{
		limiterMap:     make(map[string]*rate.Limiter),
		r:              rate.Limit(r),
		b:              b,
		addr:           addr,
		onlyUnixSocket: onlyUnixSocket,
		ports:          ports,
	}
	if err := rl.SetupIPT(); err != nil {
		log.Printf("Failed to set up iptables: %s\n", err.Error())
		os.Exit(1)
	}
	return rl
}

func (r *ReqLimiter) Start() {
	log.Printf("ReqLimiter is starting...\nRate limit(per second): %f\nBurst: %d\n", r.r, r.b)
	interruptC := make(chan os.Signal, 1)
	signal.Notify(interruptC, os.Interrupt)
	sysLogServer, sysLogChan, err := StartSysServer(r.addr, r.onlyUnixSocket)
	if err != nil {
		log.Println(err.Error())
		os.Exit(1)
	}
	go r.record(sysLogChan)
	for {
		select {
		case <-interruptC:
			log.Println("ReqLimiter stopped, clear the chain...")
			sysLogServer.Kill()
			r.ClearIPT()
			os.Exit(0)
		}
	}
}

func (r *ReqLimiter) addIP(ip string) *rate.Limiter {
	r.limiterMap[ip] = rate.NewLimiter(r.r, r.b)
	return r.limiterMap[ip]
}

func (r *ReqLimiter) getLimiter(ip string) *rate.Limiter {
	limiter, exist := r.limiterMap[ip]
	if !exist {
		return r.addIP(ip)
	}
	return limiter
}

func (r *ReqLimiter) record(lc syslog.LogPartsChannel) {
	for logParts := range lc {
		content := logParts["content"].(string)
		ls := strings.Split(content, " ")
		limiter := r.getLimiter(ls[0])
		if !limiter.Allow() {
			log.Println("Too many requests, ban", ls[0])
			// ip协议匹配
			var err1, err2 error
			if ip4Regexp.Match([]byte(ls[0])) {
				err1 = r.ipt.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "tcp", "--dports", r.ports, "-j", "DROP")
				err2 = r.ipt.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "udp", "--dports", r.ports, "-j", "DROP")
			} else if ip6Regexp.Match([]byte(ls[0])) {
				err1 = r.ip6t.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "tcp", "--dports", r.ports, "-j", "DROP")
				err2 = r.ip6t.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "udp", "--dports", r.ports, "-j", "DROP")
			} else {
				log.Println("IP address is not valid:", ls[0])
			}
			if err1 != nil || err2 != nil {
				log.Println("Failed to ban", ls[0], err1, err2)
			}
		}
	}
}

func (r *ReqLimiter) SetupIPT() error {
	var err error
	var exist bool
	// IPV4
	if r.ipt, err = iptables.New(); err != nil {
		return err
	}
	if exist, err = r.ipt.ChainExists("filter", "NGX-REQLIMITER"); err != nil {
		return err
	}
	if exist {
		if err = r.ipt.ClearChain("filter", "NGX-REQLIMITER"); err != nil {
			return err
		}
	} else {
		if err = r.ipt.NewChain("filter", "NGX-REQLIMITER"); err != nil {
			return err
		}
	}
	if err = r.ipt.AppendUnique("filter", "INPUT", "-j", "NGX-REQLIMITER"); err != nil {
		return err
	}

	// IPV6
	if r.ip6t, err = iptables.NewWithProtocol(iptables.ProtocolIPv6); err != nil {
		return err
	}
	if exist, err = r.ip6t.ChainExists("filter", "NGX-REQLIMITER"); err != nil {
		return err
	}
	if exist {
		if err = r.ip6t.ClearChain("filter", "NGX-REQLIMITER"); err != nil {
			return err
		}
	} else {
		if err = r.ip6t.NewChain("filter", "NGX-REQLIMITER"); err != nil {
			return err
		}
	}
	if err = r.ip6t.AppendUnique("filter", "INPUT", "-j", "NGX-REQLIMITER"); err != nil {
		return err
	}
	return nil
}

func (r *ReqLimiter) ClearIPT() {
	r.ipt.ClearChain("filter", "NGX-REQLIMITER")
	r.ip6t.ClearChain("filter", "NGX-REQLIMITER")
}
