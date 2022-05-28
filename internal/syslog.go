package internal

import (
	"log"
	"os"

	"gopkg.in/mcuadros/go-syslog.v2"
)

func StartSysServer(addr string, onlyUnixSocket bool) (*syslog.Server, syslog.LogPartsChannel, error) {
	logChan := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(logChan)
	server := syslog.NewServer()
	server.SetHandler(handler)
	server.SetFormat(syslog.RFC3164)

	os.Remove("/var/run/go-ngx-limiter.sock")
	os.Chmod("/var/run/go-ngx-limiter.sock", 0766)
	if err := server.ListenUnixgram("/var/run/go-ngx-limiter.sock"); err != nil {
		return nil, nil, err
	}
	if !onlyUnixSocket {
		if err := server.ListenTCP(addr); err != nil {
			return nil, nil, err
		}
		if err := server.ListenUDP(addr); err != nil {
			return nil, nil, err
		}
		log.Printf("Listening on %s and /var/run/go-ngx-limiter.sock\n", addr)
	} else {
		log.Printf("Listening on /var/run/go-ngx-limiter.sock\n")
	}
	if err := server.Boot(); err != nil {
		return nil, nil, err
	}
	return server, logChan, nil
}
