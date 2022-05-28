## Go-ngx-reqlimiter

### How to start

edit the nginx config file and add the following line:

```conf
access_log syslog:server=127.0.0.1:1514,facility=local7,tag=nginx,severity=info;
or use the unix socket in the working directory
access_log syslog:server=unix:/var/run/go-ngx-limiter.sock,facility=local7,tag=nginx,severity=info;
```

execute `./go-ngx-reqlimiter start` to start the limiter, use `-h` to see the options.

```
Flags:
  -b, --burst int     rate burst (default 100)
  -h, --help          help for start
  -i, --ip string     bind ip (default "127.0.0.1")
  -p, --port string   bind port (default "514")
  -r, --rate float    rate limit (default 50)
  -t, --toggle        Help message for toggle
  -u, --unix-only     only unix socket
``` 

### TODOs

- command when running

- write ban record to file

- support ipv6

- custom restricted ports

- config file

- custom url weight
