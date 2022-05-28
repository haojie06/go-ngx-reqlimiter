package internal

import (
	"gopkg.in/mcuadros/go-syslog.v2"
)

func StartSysServer(addr string, port string) (*syslog.Server, syslog.LogPartsChannel, error) {
	logChan := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(logChan)
	server := syslog.NewServer()
	server.SetHandler(handler)
	server.SetFormat(syslog.RFC3164)
	server.ListenTCP(addr + ":" + port)
	server.ListenUDP(addr + ":" + port)

	if err := server.Boot(); err != nil {
		return nil, nil, err
	}
	return server, logChan, nil
}
