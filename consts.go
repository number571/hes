package main

import (
	"flag"
	"time"
	"net/url"
	"net/http"
	"golang.org/x/net/proxy"
	gp "github.com/number571/gopeer"
)

const (
	TMESSAGE = "\005\007\001\000\001\007\005"
	MAXESIZE = (8 << 20) // 8MiB
	POWSDIFF = 25 // bits
)

var (
	OPENADDR = ""
	HTCLIENT = new(http.Client)
)

func hesDefaultInit(address string) {
	socks5Ptr := flag.String("socks5", "", "enable socks5 and create proxy connection")
	addrPtr := flag.String("open", address, "open address for hidden email server")
	flag.Parse()
	OPENADDR = *addrPtr
	if *socks5Ptr != "" {
		socks5, err := url.Parse("socks5://" + *socks5Ptr)
		if err != nil {
			panic("error: socks5 conn")
		}
		dialer, err := proxy.FromURL(socks5, proxy.Direct)
		if err != nil {
			panic("error: dialer")
		}
		HTCLIENT = &http.Client{
			Transport: &http.Transport{Dial: dialer.Dial},
			Timeout:   time.Second * 15,
		}
	}
	gp.Set(gp.SettingsType{
		"POWS_DIFF": uint(POWSDIFF),
	})
}
