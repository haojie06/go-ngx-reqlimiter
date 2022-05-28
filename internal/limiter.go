package internal

import (
	"fmt"
	"regexp"

	"gopkg.in/mcuadros/go-syslog.v2"
)

const ngxRegexpStr = `^((?:[0-9]{1,3}\.){3}[0-9]{1,3})\s-\s-\s\[(.+)\]\s\"([A-Z]+)\s(\S+)\s([^\"\s]+)\"\s(\d+)\s(\d+)\s\"(.+)\"\s\"(.+)\"`

type ReqRecord struct {
	IP       string
	ReqCount int
	LastTime int64
}

func StartLimitter() {
	fmt.Println("start limiter")
	ngxReg, err := regexp.Compile(ngxRegexpStr)
	if err != nil {
		panic(err.Error())
	}
	sysLogServer, sysLogChan, err := StartSysServer("127.0.0.1", "1514")
	if err != nil {
		panic(err.Error())
	}
	go Parse(ngxReg, sysLogChan)
	sysLogServer.Wait()
}

func Parse(ngxReg *regexp.Regexp, lc syslog.LogPartsChannel) {
	for logParts := range lc {
		// 正则提取出各字段
		rMap := ngxReg.FindStringSubmatch(fmt.Sprintf("%s", logParts["content"]))
		fmt.Println(rMap[1])
	}
}
