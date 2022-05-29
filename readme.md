## Go-ngx-reqlimiter

### How to start

Edit the nginx config file and add the following lines:

```conf
Add 

log_format limiter '$remote_addr $request'; 

Outside the server{}

Add

access_log syslog:server=127.0.0.1:514 limiter;

access_log syslog:server=unix:/var/run/go-ngx-limiter.sock limiter;   #or use the unix socket in the working directory

Inside the server{}
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
- custom restricted ports
- config file
- custom url weight
- whitelist url
- auto unban
- ipv6 prefix match support
- x-forward-for support
- cloudflare api
