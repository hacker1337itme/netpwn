# netpwn
netpwn

# BUILD && RUN

```shell
javac NetworkScanner.java
java NetworkScanner
```


# USAGE
```md
# Scan local network with default ports
java NetworkScanner 192.168.1.0/24

# Scan with custom ports
java NetworkScanner 10.0.0.0/24 "80,443,22,3306,8080"

# Scan single host (using /32 CIDR)
java NetworkScanner 192.168.1.100/32
```
