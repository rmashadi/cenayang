# CENAYANG Tool Scanner
A Simple Host or IP Scanner Tool with Go Language.

## List
- Nmap
- Whois
- Ping ICMP
- virus Total (On Progress Developtment)
- Shodan (*required API Key)

## Supported Operating Systems

### Linux
This library attempts to send an "unprivileged" ping via UDP. On Linux,
this must be enabled with the following sysctl command:

```
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
```

If you do not wish to do this, you can call `pinger.SetPrivileged(true)`
in your code and then use setcap on your binary to allow it to bind to
raw sockets (or just run it as root):

```
setcap cap_net_raw=+ep /path/to/your/compiled/binary
```

See [this blog](https://sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/)
and the Go [x/net/icmp](https://godoc.org/golang.org/x/net/icmp) package
for more details.
