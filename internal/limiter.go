package internal

import (
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/time/rate"
	"gopkg.in/mcuadros/go-syslog.v2"
)

type ReqLimiter struct {
	limiterMap     map[string]*rate.Limiter
	r              rate.Limit
	b              int
	addr           string
	onlyUnixSocket bool
	ipt            *iptables.IPTables
}

func NewReqLimiter(addr string, onlyUnixSocket bool, r float64, b int) *ReqLimiter {
	rl := &ReqLimiter{
		limiterMap:     make(map[string]*rate.Limiter),
		r:              rate.Limit(r),
		b:              b,
		addr:           addr,
		onlyUnixSocket: onlyUnixSocket,
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
			err1 := r.ipt.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "tcp", "--dports", "80,443", "-j", "DROP")
			err2 := r.ipt.AppendUnique("filter", "NGX-REQLIMITER", "-s", ls[0], "--match", "multiport", "-p", "udp", "--dports", "80,443", "-j", "DROP")
			if err1 != nil || err2 != nil {
				log.Println("failed to ban", ls[0], err1, err2)
			} else {
				log.Println("ban", ls[0])
			}
		}
	}
}

func (r *ReqLimiter) SetupIPT() error {
	var err error
	var exist bool
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
	return nil
}

func (r *ReqLimiter) ClearIPT() error {
	return r.ipt.ClearChain("filter", "NGX-REQLIMITER")
}
