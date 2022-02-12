package settings

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/url"
	"time"

	gp "github.com/number571/go-peer/settings"
	"golang.org/x/net/proxy"
)

const (
	AKEYSIZE = 2048
)

var (
	SETTINGS = gp.NewSettings()
	HTCLIENT = new(http.Client)
	OPENADDR = ""
)

func HesDefaultInit(address string) {
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

	SETTINGS.Set(gp.SizeWork, 25)
	SETTINGS.Set(gp.SizePack, 8<<20)
	SETTINGS.Set(gp.SizeSkey, 1<<5)
}

func Serialize(data interface{}) []byte {
	res, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return nil
	}
	return res
}
