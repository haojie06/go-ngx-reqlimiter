## Go-ngx-reqlimiter


edit the nginx config file and add the following line:

```conf
access_log syslog:server=127.0.0.1:1514,facility=local7,tag=nginx,severity=info;
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
``` 