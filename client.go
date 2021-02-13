package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	gp "github.com/number571/gopeer"
	"golang.org/x/net/proxy"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Resp struct {
	Result string `json:"result"`
	Return int    `json:"return"`
}

type Req struct {
	Recv string `json:"recv"`
	Data string `json:"data"`
}

func main() {
	var (
		httpClient = new(http.Client)
		client     = new(gp.Client)
		address    string
		message    string
		splited    []string
	)
	useTor := flag.Bool("tor", false, "enable socks5 and connect to tor network")
	addrPtr := flag.String("address", "", "connect to hidden email server")
	flag.Parse()
	if *addrPtr == "" {
		fmt.Println("error: address is nil")
		return
	}
	address = *addrPtr
	if *useTor {
		socks5, err := url.Parse("socks5://127.0.0.1:9050")
		if err != nil {
			fmt.Println("error: socks5 conn")
			return
		}
		dialer, err := proxy.FromURL(socks5, proxy.Direct)
		if err != nil {
			fmt.Println("error: dialer")
			return
		}
		httpClient = &http.Client{
			Transport: &http.Transport{Dial: dialer.Dial},
			Timeout:   time.Second * 15,
		}
	}
	for {
		message = inputString("> ")
		splited = strings.Split(message, " ")
		switch splited[0] {
		case "exit":
			os.Exit(0)
		case "help":
			fmt.Println(help())
		case "user":
			actionUser(client, splited)
		case "send":
			actionSend(httpClient, client, address)
		case "recv":
			actionRecv(httpClient, client, address, splited)
		default:
			fmt.Println("error: command undefined\n")
		}
	}
}

func help() string {
	return `
1. exit - close client;
2. help - commands info;
3. user - actions:
3.1. create - generate private key;
3.2. load - load private key;
3.3. public - print public key;
3.4. private - print private key;
4. send - send email;
5. recv - actions:
5.1. size - print number of emails;
5.2. [number] - print email by number;
`
}

func serialize(data interface{}) []byte {
	res, err := json.MarshalIndent(data, "", "\n")
	if err != nil {
		return nil
	}
	return res
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(msg, "\n", "", 1)
}

func actionUser(client *gp.Client, splited []string) {
	if len(splited) < 2 {
		fmt.Println("error: len.splited < 2\n")
		return
	}
	switch splited[1] {
	case "load":
		strpriv := inputString("[priv]> ")
		priv := gp.ParsePrivate(strpriv)
		if priv == nil {
			fmt.Println("error: parse private key\n")
			return
		}
		*client = *gp.NewClient(priv, nil)
		fmt.Println("success: user loaded\n")
	case "create":
		priv := gp.GeneratePrivate(gp.Get("AKEY_SIZE").(uint))
		*client = *gp.NewClient(priv, nil)
		fmt.Println("success: user created\n")
	case "public":
		if client.Private() == nil {
			fmt.Println("error: client is nil\n")
			return
		}
		fmt.Printf("%s\n\n", client.StringPublic())
	case "private":
		if client.Private() == nil {
			fmt.Println("error: client is nil\n")
			return
		}
		fmt.Printf("%s\n\n", client.StringPrivate())
	default:
		fmt.Println("error: command undefined\n")
	}
}

func actionSend(httpClient *http.Client, client *gp.Client, address string) {
	var result Resp
	if client.Private() == nil {
		fmt.Println("error: client is nil\n")
		return
	}
	recvstr := inputString("[recv]> ")
	recv := gp.ParsePublic(recvstr)
	if recv == nil {
		fmt.Println("error: parse public key\n")
		return
	}
	title := inputString("[head]> ")
	if title == "" {
		fmt.Println("error: title is nil\n")
		return
	}
	message := inputString("[body]> ")
	if title == "" {
		fmt.Println("error: message is nil\n")
		return
	}
	pack := gp.NewPackage(title, message)
	pack = client.Encrypt(recv, pack)
	req := serialize(Req{
		Recv: gp.HashPublic(recv),
		Data: gp.SerializePackage(pack),
	})
	resp, err := httpClient.Post(
		"http://"+address+"/send",
		"application/json",
		bytes.NewReader(req),
	)
	if err != nil {
		fmt.Println("error: send email\n")
		return
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		fmt.Println("error: parse json\n")
		return
	}
	if result.Return != 0 {
		fmt.Printf("error: server (%d) return\n\n", result.Return)
		return
	}
	fmt.Println("success: email send\n")
}

func actionRecv(httpClient *http.Client, client *gp.Client, address string, splited []string) {
	var result Resp
	if len(splited) < 2 {
		fmt.Println("error: len.splited < 2\n")
		return
	}
	if client.Private() == nil {
		fmt.Println("error: client is nil\n")
		return
	}
	switch splited[1] {
	case "size":
		req := serialize(Req{
			Recv: client.HashPublic(),
			Data: "size",
		})
		resp, err := httpClient.Post(
			"http://"+address+"/recv",
			"application/json",
			bytes.NewReader(req),
		)
		if err != nil {
			fmt.Println("error: recv size\n")
			return
		}
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			fmt.Println("error: parse json\n")
			return
		}
		if result.Return != 0 {
			fmt.Printf("error: server (%d) return\n\n", result.Return)
			return
		}
		fmt.Printf("%s\n\n", result.Result)
	default:
		_, err := strconv.Atoi(splited[1])
		if err != nil {
			fmt.Println("error: parse int\n")
			return
		}
		req := serialize(Req{
			Recv: client.HashPublic(),
			Data: splited[1],
		})
		resp, err := httpClient.Post(
			"http://"+address+"/recv",
			"application/json",
			bytes.NewReader(req),
		)
		if err != nil {
			fmt.Println("error: recv size\n")
			return
		}
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&result)
		if err != nil {
			fmt.Println("error: parse json\n")
			return
		}
		if result.Return != 0 {
			fmt.Printf("error: server (%d) return\n\n", result.Return)
			return
		}
		pack := gp.DeserializePackage(result.Result)
		pack = client.Decrypt(pack)
		if pack == nil {
			fmt.Println("error: pack is nil\n")
			return
		}
		sender := gp.ParsePublic(pack.Head.Sender)
		if sender == nil {
			fmt.Println("error: parse public key\n")
			return
		}
		fmt.Printf("Sender: %s\n%s\nTitle: '%s'\nMessage: '%s'\n\n",
			pack.Head.Sender, "---------------------------------",
			pack.Head.Title, pack.Body.Data)
	}
}
