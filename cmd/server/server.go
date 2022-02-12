package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	st "github.com/number571/hes/settings"

	cr "github.com/number571/go-peer/crypto"
	en "github.com/number571/go-peer/encoding"
	lc "github.com/number571/go-peer/local"
	gp "github.com/number571/go-peer/settings"
)

var (
	DATABASE = NewDB("s-hes.db")
	FLCONFIG = NewCFG("s-hes.cfg")
)

func init() {
	go delOldEmailsByTime(24*time.Hour, 6*time.Hour)
	st.HesDefaultInit("localhost:8080")
	fmt.Printf("Server is listening [%s] ...\n\n", st.OPENADDR)
}

func delOldEmailsByTime(deltime, period time.Duration) {
	for {
		DATABASE.DelEmailsByTime(deltime)
		time.Sleep(period)
	}
}

func main() {
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/email/send", emailSendPage)
	http.HandleFunc("/email/recv", emailRecvPage)
	http.ListenAndServe(st.OPENADDR, nil)
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Macp string `json:"macp"`
	}
	if r.Method != "POST" {
		response(w, 0, "hidden email service")
		return
	}
	if r.ContentLength > int64(st.SETTINGS.Get(gp.SizePack)) {
		response(w, 1, "error: max size")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response(w, 2, "error: parse json")
		return
	}
	pasw := cr.NewHasher([]byte(FLCONFIG.Pasw)).Bytes()
	cipher := cr.NewCipher(pasw)
	dect := cipher.Decrypt(en.Base64Decode(req.Macp))
	if !bytes.Equal(en.Uint64ToBytes(st.SETTINGS.Get(gp.MaskRout)), dect) {
		response(w, 3, "error: message authentication code")
		return
	}
	response(w, 0, "success: check connection")
}

func emailSendPage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
		Macp string `json:"macp"`
	}
	if r.Method != "POST" {
		response(w, 1, "error: method != POST")
		return
	}
	if r.ContentLength > int64(st.SETTINGS.Get(gp.SizePack)) {
		response(w, 2, "error: max size")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		response(w, 3, "error: parse json")
		return
	}
	pack := lc.Package(req.Data).Deserialize()
	if pack == nil {
		response(w, 4, "error: deserialize package")
		return
	}
	hash := pack.Body.Hash
	puzzle := cr.NewPuzzle(st.SETTINGS.Get(gp.SizeWork))
	if !puzzle.Verify(hash, pack.Body.Npow) {
		response(w, 5, "error: proof of work")
		return
	}
	pasw := cr.NewHasher([]byte(FLCONFIG.Pasw)).Bytes()
	cipher := cr.NewCipher(pasw)
	dech := cipher.Decrypt(en.Base64Decode(req.Macp))
	if !bytes.Equal(hash, dech) {
		response(w, 6, "error: message authentication code")
		return
	}
	err = DATABASE.SetEmail(req.Recv, pack)
	if err != nil {
		response(w, 7, "error: save email")
		return
	}
	for _, conn := range FLCONFIG.Conns {
		go func(conn [2]string) {
			addr := conn[0]
			pasw := cr.NewHasher([]byte(conn[1])).Bytes()
			cipher := cr.NewCipher(pasw)
			req.Macp = en.Base64Encode(cipher.Encrypt(hash))
			resp, err := st.HTCLIENT.Post(
				addr+"/email/send",
				"application/json",
				bytes.NewReader(st.Serialize(req)),
			)
			if err != nil {
				return
			}
			resp.Body.Close()
		}(conn)
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
	if r.ContentLength > int64(st.SETTINGS.Get(gp.SizePack)) {
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
