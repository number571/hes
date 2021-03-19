package main

import (
	us "./userside"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"image/png"
	"strconv"
	gp "github.com/number571/gopeer"
	"golang.org/x/net/proxy"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"
)

type TemplateResult struct {
	Auth   string
	Result string
	Return int
}

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
	HPCLIENT = new(http.Client)
	DATABASE = us.NewDB("client.db")
	SESSIONS = us.NewSessions()
)

func init() {
	torUsed  := flag.Bool("tor", false, "enable socks5 and connect to tor network")
	addrUsed := flag.String("open", "localhost:7545", "open address for gui application")
	flag.Parse()
	OPENADDR = *addrUsed
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
		name := r.FormValue("username")
		pasw := r.FormValue("password")
		spriv := r.FormValue("private_key")
		priv := gp.StringToPrivateKey(spriv)
		switch {
		case len(name) < 6 || len(name) > 64:
			retcod, result = makeResult(RET_DANGER, "need len username >= 6 and <= 64")
		case len(pasw) < 8:
			retcod, result = makeResult(RET_DANGER, "need len password >= 8")
		case pasw != r.FormValue("password_repeat"):
			retcod, result = makeResult(RET_DANGER, "passwords not equal")
		case spriv != "" && priv == nil:
			retcod, result = makeResult(RET_DANGER, "private key is not valid")
		default:
			if priv == nil {
				priv = gp.GenerateKey(gp.Get("AKEY_SIZE").(uint))
			}
			err := DATABASE.SetUser(name, pasw, priv)
			if err == nil {
				http.Redirect(w, r, "/signin", 302)
				return
			}
			retcod, result = makeResult(RET_DANGER, "username already exist")
		}
	}
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
		switch {
		case user == nil:
			retcod, result = makeResult(RET_DANGER, "username of password incorrect")
		default:
			SESSIONS.Set(w, user)
			http.Redirect(w, r, "/", 302)
			return
		}
	}
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
		switch {
		case cuser == nil || cuser.Id != user.Id:
			retcod, result = makeResult(RET_DANGER, "username of password incorrect")
		default:
			SESSIONS.Del(w, r)
			DATABASE.DelUser(cuser)
			http.Redirect(w, r, "/", 302)
			return
		}
	}
	t.Execute(w, AccountTemplateResult{
		TemplateResult: TemplateResult{
			Auth: getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		PublicKey: gp.PublicKeyToString(&user.Priv.PublicKey),
		PrivateKey: gp.PrivateKeyToString(user.Priv),
	})
}

func accountPublicKeyPage(w http.ResponseWriter, r *http.Request) {
	user := SESSIONS.Get(r)
	if user == nil {
		fmt.Fprint(w, "session is nil")
		return
	}
	dataString := gp.PublicKeyToString(&user.Priv.PublicKey)
	qrCode, err := qr.Encode(dataString, qr.Q, qr.Auto)
	if err != nil {
		fmt.Fprint(w, "qrcode generate error")
		return
	}
	qrCode, err = barcode.Scale(qrCode, 768, 768)
	if err != nil {
		fmt.Fprint(w, "qrcode scale error")
		return
	}
	png.Encode(w, qrCode)
}

func accountPrivateKeyPage(w http.ResponseWriter, r *http.Request) {
	user := SESSIONS.Get(r)
	if user == nil {
		fmt.Fprint(w, "session is nil")
		return
	}
	dataString := gp.PrivateKeyToString(user.Priv)
	qrCode, err := qr.Encode(dataString, qr.Q, qr.Auto)
	if err != nil {
		fmt.Fprint(w, "qrcode generate error")
		return
	}
	qrCode, err = barcode.Scale(qrCode, 768, 768)
	if err != nil {
		fmt.Fprint(w, "qrcode scale error")
		return
	}
	png.Encode(w, qrCode)
}

func networkPage(w http.ResponseWriter, r *http.Request) {
	type ReadTemplateResult struct {
		TemplateResult
		Page int
		Emails []us.Email
	}
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
	}
	const (
		QUAN_EMAILS_PAGE = 5
	)
	page := 0
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"network.html",
	)
	if err != nil {
		panic("error: load network.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "GET" && (r.FormValue("back") != "" || r.FormValue("next") != "") {
		num, err := strconv.Atoi(r.FormValue("num"))
		switch {
		case err != nil:
			retcod, result = makeResult(RET_DANGER, "atoi parse error")
		default:
			if r.FormValue("back") != "" {
				page = num - 1
			}
			if r.FormValue("next") != "" {
				page = num + 1
			}
		}
	}
	if r.Method == "POST" && r.FormValue("delete") != "" {
		hash := r.FormValue("email")
		DATABASE.DelEmail(user, hash)
	}
	if r.Method == "POST" && r.FormValue("update") != "" {
		var servresp Resp
		conns  := DATABASE.GetConns(user)
		client := gp.NewClient(user.Priv, nil)
		pbhash := gp.HashPublicKey(client.PublicKey())
		rdata  := serialize(Req{
			Recv: pbhash,
			Data: "size",
		})
		for _, addr := range conns {
			// GET SIZE EMAILS
			resp, err := HPCLIENT.Post(
				"http://"+addr+"/recv",
				"application/json",
				bytes.NewReader(rdata),
			)
			if err != nil {
				retcod, result = makeResult(RET_WARNING, 
					result + fmt.Sprintf("send error: '%s'; ", addr))
				continue
			}
			err = json.NewDecoder(resp.Body).Decode(&servresp)
			resp.Body.Close()
			if err != nil {
				retcod, result = makeResult(RET_WARNING, 
					result + fmt.Sprintf("parse json: '%s'; ", addr))
				continue
			}
			if servresp.Return != 0 {
				retcod, result = makeResult(RET_WARNING, 
					result + fmt.Sprintf("return (%d): '%s'; ", servresp.Return, addr))
				continue
			}
			// GET DATA EMAILS
			size, err := strconv.Atoi(servresp.Result)
			if err != nil {
				retcod, result = makeResult(RET_WARNING, 
					result + fmt.Sprintf("parse int: '%s'; ", addr))
				continue
			}
			for i := 1; i <= size; i++ {
				req := serialize(Req{
					Recv: pbhash,
					Data: fmt.Sprintf("%d", i),
				})
				resp, err := HPCLIENT.Post(
					"http://"+addr+"/recv",
					"application/json",
					bytes.NewReader(req),
				)
				if err != nil {
					continue 
				}
				err = json.NewDecoder(resp.Body).Decode(&servresp)
				resp.Body.Close()
				if err != nil {
					continue
				}
				if servresp.Return != 0 {
					continue
				}
				pack := gp.DeserializePackage(servresp.Result)
				pack = client.Decrypt(pack)
				if pack == nil {
					continue
				}
				DATABASE.SetEmail(user, pack)
			}
		}
	}
	emails := DATABASE.GetEmails(user, page*QUAN_EMAILS_PAGE, QUAN_EMAILS_PAGE)
	t.Execute(w, ReadTemplateResult{
		TemplateResult: TemplateResult{
			Auth:   getName(SESSIONS.Get(r)),
			Result: result,
			Return: retcod,
		},
		Page:   page,
		Emails: emails,
	})
}

func networkWritePage(w http.ResponseWriter, r *http.Request) {
	type Resp struct {
		Result string `json:"result"`
		Return int    `json:"return"`
	}
	type Req struct {
		Recv string `json:"recv"`
		Data string `json:"data"`
	}
	retcod, result := makeResult(RET_SUCCESS, "")
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"write.html",
	)
	if err != nil {
		panic("error: load network.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" {
		client := gp.NewClient(user.Priv, nil)
		recv := gp.StringToPublicKey(r.FormValue("receiver"))
		pack := gp.NewPackage(
			user.Name + us.SEPARATOR + r.FormValue("title"), 
			r.FormValue("message"),
		)
		switch {
		case recv == nil:
			retcod, result = makeResult(RET_DANGER, "receiver is nil")
		default:
			var servresp Resp
			conns := DATABASE.GetConns(user)
			rdata := serialize(Req{
				Recv: gp.HashPublicKey(recv),
				Data: gp.SerializePackage(client.Encrypt(recv, pack)),
			})
			for _, addr := range conns {
				resp, err := HPCLIENT.Post(
					"http://"+addr+"/send",
					"application/json",
					bytes.NewReader(rdata),
				)
				if err != nil {
					retcod, result = makeResult(RET_WARNING, 
						fmt.Sprintf("send error: '%s'\n", addr))
					continue
				}
				err = json.NewDecoder(resp.Body).Decode(&servresp)
				resp.Body.Close()
				if err != nil {
					retcod, result = makeResult(RET_WARNING, 
						fmt.Sprintf("parse json: '%s'\n", addr))
					continue
				}
				if servresp.Return != 0 {
					retcod, result = makeResult(RET_WARNING, 
						fmt.Sprintf("return (%d): '%s'\n", servresp.Return, addr))
					continue
				}
			}
		}
	}
	t.Execute(w, TemplateResult{
		Auth:   getName(SESSIONS.Get(r)),
		Result: result,
		Return: retcod,
	})
}

func networkReadPage(w http.ResponseWriter, r *http.Request) {
	type ReadTemplateResult struct {
		TemplateResult
		Email *us.Email
	}
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"read.html",
	)
	if err != nil {
		panic("error: load read.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	var email *us.Email
	id, err := strconv.Atoi(r.FormValue("email"))
	if err == nil {
		email = DATABASE.GetEmail(user, id)
	}
	if email == nil {
		fmt.Fprint(w, "email undefined")
		return
	}
	t.Execute(w, ReadTemplateResult{
		TemplateResult: TemplateResult{
			Auth: getName(SESSIONS.Get(r)),
		},
		Email: email,
	})
}

func networkConnectPage(w http.ResponseWriter, r *http.Request) {
	type ConnTemplateResult struct {
		TemplateResult
		Connects []string
	}
	t, err := template.ParseFiles(
		PATH_VIEWS+"base.html",
		PATH_VIEWS+"connect.html",
	)
	if err != nil {
		panic("error: load network.html")
	}
	user := SESSIONS.Get(r)
	if user == nil {
		http.Redirect(w, r, "/", 302)
		return
	}
	if r.Method == "POST" {
		host := r.FormValue("hostname")
		if r.FormValue("append") != "" {
			DATABASE.SetConn(user, host)
		}
		if r.FormValue("delete") != "" {
			DATABASE.DelConn(user, host)
		}
	}
	t.Execute(w, ConnTemplateResult{
		TemplateResult: TemplateResult{
			Auth: getName(SESSIONS.Get(r)),
		},
		Connects: DATABASE.GetConns(user),
	})
}

func getName(user *us.User) string {
	if user == nil {
		return ""
	}
	return user.Name
}

func makeResult(retcod int, result string) (int, string) {
	return retcod, result
}

func serialize(data interface{}) []byte {
	res, err := json.MarshalIndent(data, "", "\n")
	if err != nil {
		return nil
	}
	return res
}
