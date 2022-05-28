package internal

import (
	"fmt"
	"regexp"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/time/rate"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const ngxRegexpStr = `^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s-\s-\s\[(.+)\]\s\"([A-Z]+)\s(\S+)\s([^\"\s]+)\"\s(\d+)\s(\d+)\s\"(.+)\"\s\"(.+)\"`

type ReqLimiter struct {
	limiterMap map[string]*rate.Limiter
	r          rate.Limit
	b          int
	ipt        *iptables.IPTables
}

func NewReqLimiter(r rate.Limit, b int) *ReqLimiter {
	rl := &ReqLimiter{
		limiterMap: make(map[string]*rate.Limiter),
		r:          r,
		b:          b,
	}
	if err := rl.setupIPT(); err != nil {
		panic(err.Error())
	}
	return rl
}

func (r *ReqLimiter) Start() {
	fmt.Println("start limiter")
	ngxReg, err := regexp.Compile(ngxRegexpStr)
	if err != nil {
		panic(err.Error())
	}
	sysLogServer, sysLogChan, err := StartSysServer("127.0.0.1", "1514")
	if err != nil {
		panic(err.Error())
	}
	go r.record(ngxReg, sysLogChan)
	sysLogServer.Wait()
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
		fmt.Println(rMap[1])
		limiter := r.getLimiter(rMap[1])
		if !limiter.Allow() {
			r.ipt.AppendUnique("filter", "ngx-reqlimiter", "-s", rMap[1], "--dport", "-p", "tcp", "80,443", "-j", "DROP")
			r.ipt.AppendUnique("filter", "ngx-reqlimiter", "-s", rMap[1], "--dport", "-p", "udp", "80,443", "-j", "DROP")
			fmt.Println("too many request", rMap[1])
		}
	}
}

func (r *ReqLimiter) setupIPT() error {
	var ipt *iptables.IPTables
	var err error
	if ipt, err = iptables.New(); err != nil {
		return err
	}
	if err = ipt.ClearAndDeleteChain("filter", "limiter"); err != nil {
		return err
	}
	if err = r.ipt.NewChain("filter", "ngx-reqlimiter"); err != nil {
		return err
	}
	if err = r.ipt.Insert("filter", "INPUT", 1, "-j", "ngx-reqlimiter"); err != nil {
		return err
	}
	r.ipt = ipt
	return nil
}
