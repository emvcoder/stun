# Stun client
Simple implementation of the stun client written on Go (RFC 5389 specification). 
For more information - https://tools.ietf.org/html/rfc5389
# Installing
```shell
go get github.com/emvcoder/stun
```
# Usage
First of all you need setup default stun server:
```golang
stun.Set("stun1.l.google.com", "19302")
```
then you can create request and decode received data:
```golang
response, err := stun.Get()
```
response will be like this:
```
Address: 44.122.25.190
Port: 53782
```

Have fun!
