package internal

import (
	"log"

	"gopkg.in/mcuadros/go-syslog.v2"
)

func StartSysServer(addr string, onlyUnixSocket bool) (*syslog.Server, syslog.LogPartsChannel, error) {
	logChan := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(logChan)
	server := syslog.NewServer()
	server.SetHandler(handler)
	server.SetFormat(syslog.RFC3164)

	server.ListenUnixgram("/var/run/go-ngx-limiter.sock")
	if !onlyUnixSocket {
		server.ListenTCP(addr)
		server.ListenUDP(addr)
		log.Printf("Listening on %s and /var/run/go-ngx-limiter.sock\n", addr)
	} else {
		log.Printf("Listening on /var/run/go-ngx-limiter.sock\n")
	}
	if err := server.Boot(); err != nil {
		return nil, nil, err
	}
	return server, logChan, nil
}
