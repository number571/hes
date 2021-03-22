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
	"strings"
	"time"
)

const (
	MAXESIZE = (32 << 20) // 32MiB
)

var (
	OPENADDR = ""
	HPCLIENT = new(http.Client)
	DATABASE = NewDB("server.db")
)

func init() {
	torUsed := flag.Bool("tor", false, "enable socks5 and connect to tor network")
	addrPtr := flag.String("open", "localhost:8080", "open address for hidden email server")
	flag.Parse()
	OPENADDR = *addrPtr
	if *torUsed {
		socks5, err := url.Parse("socks5://127.0.0.1:9050")
		if err != nil {
			panic("error: socks5 conn")
		}
		dialer, err := proxy.FromURL(socks5, proxy.Direct)
		if err != nil {
			panic("error: dialer")
		}
		HPCLIENT = &http.Client{
			Transport: &http.Transport{Dial: dialer.Dial},
			Timeout:   time.Second * 15,
		}
	}
	fmt.Println("Server is listening...\n")
}

func main() {
	go func() {
		for {
			DATABASE.DelEmailsByTime(24 * time.Hour)
			time.Sleep(6 * time.Hour)
		}
	}()
	go func() {
		var (
			message string
			splited []string
		)
		for {
			message = inputString("> ")
			splited = strings.Split(message, " ")
			switch splited[0] {
			case "exit":
				os.Exit(0)
			case "help":
				fmt.Println(help())
			case "list":
				conns := DATABASE.GetConns()
				for _, addr := range conns {
					fmt.Printf("| %s\n", addr)
				}
				fmt.Println()
			case "append":
				if len(splited) < 2 {
					fmt.Println("error: len.message < 2\n")
					continue
				}
				DATABASE.SetConn(splited[1])
			case "delete":
				if len(splited) < 2 {
					fmt.Println("error: len.message < 2\n")
					continue
				}
				DATABASE.DelConn(splited[1])
			default:
				fmt.Println("error: undefined command\n")
			}
		}
	}()
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/email/send", emailSendPage)
	http.HandleFunc("/email/recv", emailRecvPage)
	http.ListenAndServe(OPENADDR, nil)
}

func help() string {
	return `
1. exit   - close server;
2. help   - commands info;
3. list   - list connections;
4. append - append connect to list;
5. delete - delete connect from list;
`
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(msg, "\r\n", "", 1)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	response(w, 0, "Hidden service.")
}

func emailSendPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
	}
	if r.Method != "POST" {
		response(w, 1, "error: method != POST")
		return
	}
	if r.ContentLength > MAXESIZE {
		response(w, 2, "error: max size")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response(w, 3, "error: parse json")
		return
	}
	pack := gp.DeserializePackage(req.Data)
	if pack == nil {
		response(w, 4, "error: deserialize package")
		return
	}
	hash := gp.Base64Decode(pack.Body.Hash)
	powd := gp.Get("POWS_DIFF").(uint)
	if !gp.ProofIsValid(hash, powd, pack.Body.Npow) {
		response(w, 5, "error: proof of work")
		return
	}
	err = DATABASE.SetEmail(req.Recv, pack.Body.Hash, req.Data)
	if err != nil {
		response(w, 6, "error: save email")
		return
	}
	conns := DATABASE.GetConns()
	for _, addr := range conns {
		resp, err := HPCLIENT.Post(
			"http://"+addr+"/email/send",
			"application/json",
			bytes.NewReader(serialize(req)),
		)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
	response(w, 0, "success: email saved")
}

func emailRecvPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Recv string `json:"recv"`
		Data int    `json:"data"`
	}
	if r.Method != "POST" {
		response(w, 1, "error: method != POST")
		return
	}
	if r.ContentLength > MAXESIZE {
		response(w, 2, "error: max size")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response(w, 3, "error: parse json")
		return
	}
	if req.Data == 0 {
		response(w, 0, fmt.Sprintf("%d", DATABASE.Size(req.Recv)))
		return
	}
	res := DATABASE.GetEmail(req.Data, req.Recv)
	if res == "" {
		response(w, 4, "error: nothing data")
		return
	}
	response(w, 0, res)
}

func response(w http.ResponseWriter, ret int, res string) {
	w.Header().Set("Content-Type", "application/json")
	var resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	resp.Result = res
	resp.Return = ret
	json.NewEncoder(w).Encode(resp)
}

func serialize(data interface{}) []byte {
	res, err := json.MarshalIndent(data, "", "\n")
	if err != nil {
		return nil
	}
	return res
}
