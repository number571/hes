package main

import (
	"encoding/json"
	"flag"
	"fmt"
	gp "github.com/number571/gopeer"
	"net/http"
	"strconv"
)

const (
	MAXSIZE = 32 * (1 << 20) // 32MiB
)

var (
	DBptr *DB
)

func init() {
	DBptr = DBInit("database.db")
	if DBptr == nil {
		panic("error: database init")
	}
	fmt.Println("Server is listening...\n")
}

func main() {
	addrPtr := flag.String("address", "", "address of hidden email server")
	flag.Parse()
	if *addrPtr == "" {
		fmt.Println("error: address is nil")
		return
	}
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/send", emailSendPage)
	http.HandleFunc("/recv", emailRecvPage)
	http.ListenAndServe(*addrPtr, nil)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response(w, 0, "(HES) Hidden email service. Gopeer based.")
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
	if r.ContentLength > MAXSIZE {
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
	err = DBptr.SetEmail(req.Recv, pack.Body.Hash, req.Data)
	if err != nil {
		response(w, 6, "error: save email")
		return
	}
	response(w, 0, "success: email saved")
}

func emailRecvPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
	}
	if r.Method != "POST" {
		response(w, 1, "error: method != POST")
		return
	}
	if r.ContentLength > MAXSIZE {
		response(w, 2, "error: max size")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response(w, 3, "error: parse json")
		return
	}
	switch req.Data {
	case "size":
		response(w, 0, fmt.Sprintf("%d", DBptr.Size(req.Recv)))
		return
	default:
		num, err := strconv.Atoi(req.Data)
		if err != nil {
			response(w, 4, "error: parse int")
			return
		}
		res := DBptr.GetEmail(num, req.Recv)
		if res == "" {
			response(w, 5, "error: nothing data")
			return
		}
		response(w, 0, res)
		return
	}
	response(w, 6, "error: mode undefined")
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
