package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	gp "github.com/number571/gopeer"
	"golang.org/x/net/proxy"
	"html/template"
	"image/png"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type TemplateResult struct {
	Auth   string
	Result string
	Return int
}

const (
	TMESSAGE = "\005\007\001\000\001\007\005"
	MAXESIZE = (5 << 20) // 5MiB
	POWSDIFF = 25
	MAXEPAGE = 5
	MAXCOUNT = 5
)

const (
	RET_SUCCESS = 0
	RET_DANGER  = 1
	RET_WARNING = 2
)

const (
	PATH_VIEWS  = "userside/views/"
	PATH_STATIC = "userside/static/"
)

var (
	OPENADDR = ""
	HTCLIENT = new(http.Client)
	DATABASE = NewDB("client.db")
	SESSIONS = NewSessions()
)

func init() {
	socks5Ptr := flag.String("socks5", "", "enable socks5 and create proxy connection")
	addrPtr := flag.String("open", "localhost:7545", "open address for gui application")
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
	packageDifficulty(POWSDIFF)
	go delOldSessionsByTime(1*time.Hour, 15*time.Minute)
	fmt.Println("Client is listening...\n")
}

func packageDifficulty(bits int) {
	gp.Set(gp.SettingsType{
		"POWS_DIFF": uint(bits),
	})
}

func delOldSessionsByTime(deltime, period time.Duration) {
	for {
		SESSIONS.DelByTime(deltime)
		time.Sleep(period)
	}
}

func main() {
	http.Handle("/static/", http.StripPrefix(
		"/static/",
		handleFileServer(http.Dir(PATH_STATIC))),
	)
	http.HandleFunc("/", indexPage)
	http.HandleFunc("/account", accountPage)
	http.HandleFunc("/account/public_key", accountPublicKeyPage)
	http.HandleFunc("/account/private_key", accountPrivateKeyPage)
	http.HandleFunc("/signup", signupPage)
	http.HandleFunc("/signin", signinPage)
	http.HandleFunc("/signout", signoutPage)
	http.HandleFunc("/network", networkPage)
	http.HandleFunc("/network/read", networkReadPage)
	http.HandleFunc("/network/write", networkWritePage)
	http.HandleFunc("/network/contact", networkContactPage)
	http.HandleFunc("/network/connect", networkConnectPage)
	http.ListenAndServe(OPENADDR, nil)
}

func handleFileServer(fs http.FileSystem) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Open(r.URL.Path); os.IsNotExist(err) {
			indexPage(w, r)
			return
		}
		http.FileServer(fs).ServeHTTP(w, r)
	})
}

func indexPage(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"index.html",
	)
	if err != nil {
		panic("error: load index.html")
	}
	t.Execute(w, TemplateResult{
		Auth: getName(SESSIONS.Get(r)),
	})
}

func signupPage(w http.ResponseWriter, r *http.Request) {
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"signup.html",
	)
	if err != nil {
		panic("error: load signup.html")
	}
	if SESSIONS.Get(r) != nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" {
		name := strings.TrimSpace(r.FormValue("username"))
		pasw := r.FormValue("password")
		spriv := r.FormValue("private_key")
		priv := gp.StringToPrivateKey(spriv)
		if len(name) < 6 || len(name) > 64 {
			retcod, result = makeResult(RET_DANGER, "error: need len username >= 6 and <= 64")
			goto close
		}
		if len(pasw) < 8 {
			retcod, result = makeResult(RET_DANGER, "error: need len password >= 8")
			goto close
		}
		if pasw != r.FormValue("password_repeat") {
			retcod, result = makeResult(RET_DANGER, "error: passwords not equal")
			goto close
		}
		if spriv != "" && priv == nil {
			retcod, result = makeResult(RET_DANGER, "error: private key is not valid")
			goto close
		}
		if priv == nil {
			priv = gp.GenerateKey(gp.Get("AKEY_SIZE").(uint))
		}
		err := DATABASE.SetUser(name, pasw, priv)
		if err != nil {
			retcod, result = makeResult(RET_DANGER, "error: username already exist")
			goto close
		}
		http.Redirect(w, r, "/signin", 302)
		return
	}
close:
	t.Execute(w, TemplateResult{
		Result: result,
		Return: retcod,
	})
}

func signinPage(w http.ResponseWriter, r *http.Request) {
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"signin.html",
	)
	if err != nil {
		panic("error: load signin.html")
	}
	if SESSIONS.Get(r) != nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" {
		name := r.FormValue("username")
		pasw := r.FormValue("password")
		user := DATABASE.GetUser(name, pasw)
		if user == nil {
			retcod, result = makeResult(RET_DANGER, "error: username of password incorrect")
			goto close
		}
		SESSIONS.Set(w, user)
		http.Redirect(w, r, "/", 302)
		return
	}
close:
	t.Execute(w, TemplateResult{
		Result: result,
		Return: retcod,
	})
}

func signoutPage(w http.ResponseWriter, r *http.Request) {
	SESSIONS.Del(w, r)
	http.Redirect(w, r, "/", 302)
}

func accountPage(w http.ResponseWriter, r *http.Request) {
	type AccountTemplateResult struct {
		TemplateResult
		PublicKey  string
		PrivateKey string
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"account.html",
	)
	if err != nil {
		panic("error: load account.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" && r.FormValue("delete") != "" {
		name := r.FormValue("username")
		pasw := r.FormValue("password")
		cuser := DATABASE.GetUser(name, pasw)
		if cuser == nil || cuser.Id != user.Id {
			retcod, result = makeResult(RET_DANGER, "error: username of password incorrect")
			goto close
		}
		SESSIONS.Del(w, r)
		DATABASE.DelUser(cuser)
		http.Redirect(w, r, "/", 302)
		return
	}
close:
	t.Execute(w, AccountTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		PublicKey:  gp.PublicKeyToString(&user.Priv.PublicKey),
		PrivateKey: gp.PrivateKeyToString(user.Priv),
	})
}

func accountPublicKeyPage(w http.ResponseWriter, r *http.Request) {
	user := SESSIONS.Get(r)
	if user == nil {
		fmt.Fprint(w, "error: session is null")
		return
	}
	dataString := gp.PublicKeyToString(&user.Priv.PublicKey)
	qrCode, err := qr.Encode(dataString, qr.Q, qr.Auto)
	if err != nil {
		fmt.Fprint(w, "error: qrcode generate")
		return
	}
	qrCode, err = barcode.Scale(qrCode, 768, 768)
	if err != nil {
		fmt.Fprint(w, "error: qrcode scale")
		return
	}
	png.Encode(w, qrCode)
}

func accountPrivateKeyPage(w http.ResponseWriter, r *http.Request) {
	user := SESSIONS.Get(r)
	if user == nil {
		fmt.Fprint(w, "error: session is null")
		return
	}
	dataString := gp.PrivateKeyToString(user.Priv)
	qrCode, err := qr.Encode(dataString, qr.Q, qr.Auto)
	if err != nil {
		fmt.Fprint(w, "error: qrcode generate")
		return
	}
	qrCode, err = barcode.Scale(qrCode, 768, 768)
	if err != nil {
		fmt.Fprint(w, "error: qrcode scale")
		return
	}
	png.Encode(w, qrCode)
}

func networkPage(w http.ResponseWriter, r *http.Request) {
	type ReadTemplateResult struct {
		TemplateResult
		Page   int
		Emails []Email
	}
	page := 0
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.New("base.html").Funcs(template.FuncMap{
		"inc": func(x int) int { return x + 1 },
		"dec": func(x int) int { return x - 1 },
	}).ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"network.html",
	)
	if err != nil {
		panic("error: load network.html")
	}
	t = template.Must(t, err)
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "GET" && r.FormValue("page") != "" {
		num, err := strconv.Atoi(r.FormValue("num"))
		if err != nil {
			retcod, result = makeResult(RET_DANGER, "error: parse atoi")
			goto close
		}
		page = num
	}
	if r.Method == "POST" && r.FormValue("delete") != "" {
		hash := r.FormValue("email")
		DATABASE.DelEmail(user, hash)
	}
	if r.Method == "POST" && r.FormValue("update") != "" {
		conns := DATABASE.GetConns(user)
		for _, conn := range conns {
			go readEmails(user, conn[0])
		}
		time.Sleep(3 * time.Second)
	}
close:
	t.Execute(w, ReadTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		Page:   page,
		Emails: DATABASE.GetEmails(user, page*MAXEPAGE, MAXEPAGE),
	})
}

func networkWritePage(w http.ResponseWriter, r *http.Request) {
	type WriteTemplateResult struct {
		TemplateResult
		Contacts map[string]string
	}
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
		Macp string `json:"macp"`
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"write.html",
	)
	if err != nil {
		panic("error: load write.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" {
		recv := gp.StringToPublicKey(r.FormValue("receiver"))
		if recv == nil {
			retcod, result = makeResult(RET_DANGER, "error: receiver is null")
			goto close
		}
		head := strings.TrimSpace(r.FormValue("title"))
		body := strings.TrimSpace(r.FormValue("message"))
		if head == "" || body == "" {
			retcod, result = makeResult(RET_DANGER, "error: head or body is null")
			goto close
		}
		client := gp.NewClient(user.Priv, nil)
		pack   := client.Encrypt(recv, newEmail(user.Name, head, body))
		hash   := gp.Base64Decode(pack.Body.Hash)
		conns  := DATABASE.GetConns(user)
		req    := Req{
			Recv: gp.HashPublicKey(recv),
			Data: gp.SerializePackage(pack),
		}
		for _, conn := range conns {
			pasw := gp.HashSum([]byte(conn[1]))
			req.Macp = gp.Base64Encode(gp.EncryptAES(pasw, hash))
			go writeEmails(conn[0], serialize(req))
		}
	}
close:
	t.Execute(w, WriteTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		Contacts: DATABASE.GetContacts(user),
	})
}

func networkReadPage(w http.ResponseWriter, r *http.Request) {
	type ReadTemplateResult struct {
		TemplateResult
		Email *Email
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.New("base.html").Funcs(template.FuncMap{
		"split": strings.Split,
	}).ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"read.html",
	)
	if err != nil {
		panic("error: load read.html")
	}
	t = template.Must(t, err)
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	var email *Email
	id, err := strconv.Atoi(r.FormValue("email"))
	if err != nil {
		retcod, result = makeResult(RET_DANGER, "error: atoi parse")
		goto close
	}
	email = DATABASE.GetEmail(user, id)
	if email == nil {
		retcod, result = makeResult(RET_DANGER, "error: email undefined")
		goto close
	}
close:
	t.Execute(w, ReadTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		Email: email,
	})
}

func networkContactPage(w http.ResponseWriter, r *http.Request) {
	type ContactTemplateResult struct {
		TemplateResult
		F2F bool
		Contacts map[string]string
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"contact.html",
	)
	if err != nil {
		panic("error: load contact.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" && r.FormValue("switchf2f") != "" {
		DATABASE.SwitchF2F(user)
	}
	if r.Method == "POST" && r.FormValue("append") != "" {
		name := strings.TrimSpace(r.FormValue("nickname"))
		if name == "" {
			retcod, result = makeResult(RET_DANGER, "error: nickname is null")
			goto close
		}
		publ := gp.StringToPublicKey(r.FormValue("public_key"))
		if publ == nil {
			retcod, result = makeResult(RET_DANGER, "error: public key is null")
			goto close
		}
		err := DATABASE.SetContact(user, name, publ)
		if err != nil {
			retcod, result = makeResult(RET_DANGER, "error: contact already exist")
			goto close
		}
	}
	if r.Method == "POST" && r.FormValue("delete") != "" {
		publ := gp.StringToPublicKey(r.FormValue("public_key"))
		if publ == nil {
			retcod, result = makeResult(RET_DANGER, "error: public key is null")
			goto close
		}
		DATABASE.DelContact(user, publ)
	}
close:
	t.Execute(w, ContactTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		F2F: DATABASE.StateF2F(user),
		Contacts: DATABASE.GetContacts(user),
	})
}

func networkConnectPage(w http.ResponseWriter, r *http.Request) {
	type ConnTemplateResult struct {
		TemplateResult
		Connects [][2]string
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"connect.html",
	)
	if err != nil {
		panic("error: load connect.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" && r.FormValue("check") != "" {
		conns := DATABASE.GetConns(user)
		for _, conn := range conns {
			ret, res := checkConnection(conn)
			if ret != RET_SUCCESS {
				result += res
				retcod = RET_WARNING
			}
		}
		if retcod != RET_SUCCESS {
			goto close
		}
		result = "success: all connections work"
	}
	if r.Method == "POST" && r.FormValue("append") != "" {
		host := strings.TrimSpace(r.FormValue("hostname"))
		if host == "" {
			retcod, result = makeResult(RET_DANGER, "error: string is null")
			goto close
		}
		pasw := r.FormValue("password")
		DATABASE.SetConn(user, host, pasw)
	}
	if r.Method == "POST" && r.FormValue("delete") != "" {
		host := strings.TrimSpace(r.FormValue("hostname"))
		if host == "" {
			retcod, result = makeResult(RET_DANGER, "error: string is null")
			goto close
		}
		DATABASE.DelConn(user, host)
	}
close:
	t.Execute(w, ConnTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		Connects: DATABASE.GetConns(user),
	})
}

func checkConnection(conn [2]string) (int, string) {
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Macp string `json:"macp"`
	}
	var servresp Resp
	pasw := gp.HashSum([]byte(conn[1]))
	macp := gp.EncryptAES(pasw, []byte(TMESSAGE))
	resp, err := HTCLIENT.Post(
		"http://"+conn[0]+"/",
		"application/json",
		bytes.NewReader(serialize(Req{
			Macp: gp.Base64Encode(macp),
		})),
	)
	if err != nil {
		return makeResult(RET_DANGER, 
			fmt.Sprintf("%s='%s';\n", conn[0], "error: connect"))
	}
	if resp.ContentLength > MAXESIZE {
		return makeResult(RET_DANGER, 
			fmt.Sprintf("%s='%s';\n", conn[0], "error: max size"))
	}
	err = json.NewDecoder(resp.Body).Decode(&servresp)
	resp.Body.Close()
	if err != nil {
		return makeResult(RET_DANGER, 
			fmt.Sprintf("%s='%s';\n", conn[0], "error: parse json"))
	}
	if servresp.Return != 0 {
		return makeResult(RET_DANGER, 
			fmt.Sprintf("%s='%s';\n", conn[0], servresp.Result))
	}
	return makeResult(RET_SUCCESS, "")
}

func writeEmails(addr string, rdata []byte) {
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Recv string `json:"recv"`
		Data int    `json:"data"`
	}
	var servresp Resp
	resp, err := HTCLIENT.Post(
		"http://"+addr+"/email/send",
		"application/json",
		bytes.NewReader(rdata),
	)
	if err != nil {
		return
	}
	if resp.ContentLength > MAXESIZE {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&servresp)
	resp.Body.Close()
	if err != nil {
		return
	}
	if servresp.Return != 0 {
		return
	}
}

func readEmails(user *User, addr string) {
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Recv string `json:"recv"`
		Data int    `json:"data"`
	}
	var servresp Resp
	client := gp.NewClient(user.Priv, nil)
	pbhash := gp.HashPublicKey(client.PublicKey())
	// GET SIZE EMAILS
	resp, err := HTCLIENT.Post(
		"http://"+addr+"/email/recv",
		"application/json",
		bytes.NewReader(serialize(Req{
			Recv: pbhash,
			Data: 0,
		})),
	)
	if err != nil {
		return
	}
	if resp.ContentLength > MAXESIZE {
		return
	}
	err = json.NewDecoder(resp.Body).Decode(&servresp)
	resp.Body.Close()
	if err != nil {
		return
	}
	if servresp.Return != 0 {
		return
	}
	// GET DATA EMAILS
	size, err := strconv.Atoi(servresp.Result)
	if err != nil {
		return
	}
	for i, count := 1, 0; i <= size; i++ {
		resp, err := HTCLIENT.Post(
			"http://"+addr+"/email/recv",
			"application/json",
			bytes.NewReader(serialize(Req{
				Recv: pbhash,
				Data: i,
			})),
		)
		if err != nil {
			break
		}
		if resp.ContentLength > MAXESIZE {
			break
		}
		err = json.NewDecoder(resp.Body).Decode(&servresp)
		resp.Body.Close()
		if err != nil {
			break
		}
		if servresp.Return != 0 {
			continue
		}
		pack := gp.DeserializePackage(servresp.Result)
		pack = client.Decrypt(pack)
		if pack == nil {
			continue
		}
		err = DATABASE.SetEmail(user, pack)
		if err == nil {
			count++
		}
		if count == MAXCOUNT {
			break
		}
	}
}

func newEmail(sender, head, body string) *gp.Package {
	return gp.NewPackage(IS_EMAIL, string(serialize(Email{
		SenderName: sender,
		Head:       head,
		Body:       body,
	})))
}

func getName(user *User) string {
	if user == nil {
		return ""
	}
	return user.Name
}

func makeResult(retcod int, result string) (int, string) {
	return retcod, result
}

func serialize(data interface{}) []byte {
	res, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return nil
	}
	return res
}
