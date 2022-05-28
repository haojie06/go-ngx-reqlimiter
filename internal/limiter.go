package internal

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/time/rate"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const ngxRegexpStr = `^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s-\s-\s\[(.+)\]\s\"([A-Z]+)\s(\S+)\s([^\"\s]+)\"\s(\d+)\s(\d+)\s\"(.+)\"\s\"(.+)\"`

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
		fmt.Printf("failed to set up iptables: %s", err.Error())
		os.Exit(1)
	}
	return rl
}

func (r *ReqLimiter) Start() {
	log.Printf("ReqLimiter is starting...\nRate limit(per second): %f\nBurst: %d\n", r.r, r.b)
	interruptC := make(chan os.Signal, 1)
	signal.Notify(interruptC, os.Interrupt)

	ngxReg, err := regexp.Compile(ngxRegexpStr)
	if err != nil {
		panic(err.Error())
	}
	sysLogServer, sysLogChan, err := StartSysServer(r.addr, r.onlyUnixSocket)
	if err != nil {
		panic(err.Error())
	}
	go r.record(ngxReg, sysLogChan)
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

func (r *ReqLimiter) record(ngxReg *regexp.Regexp, lc syslog.LogPartsChannel) {
	for logParts := range lc {
		// 正则提取出各字段
		rMap := ngxReg.FindStringSubmatch(fmt.Sprintf("%s", logParts["content"]))
		limiter := r.getLimiter(rMap[1])
		if !limiter.Allow() {

			log.Println("Too many requests, ban", rMap[1])
			err1 := r.ipt.AppendUnique("filter", "ngx-reqlimiter", "-s", rMap[1], "--match", "multiport", "-p", "tcp", "--dports", "80,443", "-j", "DROP")
			err2 := r.ipt.AppendUnique("filter", "ngx-reqlimiter", "-s", rMap[1], "--match", "multiport", "-p", "udp", "--dports", "80,443", "-j", "DROP")
			if err1 != nil || err2 != nil {
				log.Println("failed to ban", rMap[1])
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
	if exist, err = r.ipt.ChainExists("filter", "ngx-reqlimiter"); err != nil {
		return err
	}
	if exist {
		if err = r.ipt.ClearChain("filter", "ngx-reqlimiter"); err != nil {
			return err
		}
	} else {
		if err = r.ipt.NewChain("filter", "ngx-reqlimiter"); err != nil {
			return err
		}
	}
	if err = r.ipt.AppendUnique("filter", "INPUT", "-j", "ngx-reqlimiter"); err != nil {
		return err
	}
	return nil
}

func (r *ReqLimiter) ClearIPT() error {
	return r.ipt.ClearChain("filter", "ngx-reqlimiter")
}
