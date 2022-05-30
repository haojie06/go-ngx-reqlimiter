## Go-ngx-reqlimiter

### How to start

Edit the nginx config file and add the following lines:

```conf
# Add 

log_format limiter '$remote_addr $request'; 

# Outside the server{}

# Add

access_log syslog:server=127.0.0.1:514 limiter;
# or use the unix socket file
access_log syslog:server=unix:/var/run/go-ngx-limiter.sock limiter;   

# Inside the server{}
# Don't forget to use systemctl restart nginx to restart the nginx.
```

execute `./go-ngx-reqlimiter start -r 10 -b 100` to start the limiter, use `-h` to see the options.

```
Flags:
  -b, --burst int      Rate burst (default 100)
  -h, --help           help for start
  -i, --ip string      Bind ip (default "127.0.0.1")
  -p, --port string    Bind port (default "514")
      --ports string   Ports to protect, separated by comma (default "80,443")
  -r, --rate float     Rate limit (default 50)
  -t, --toggle         Help message for toggle
  -u, --unix-only      Using unix socket only
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
