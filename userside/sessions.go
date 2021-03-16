package userside

import (
	gp "github.com/number571/gopeer"
	"net/http"
)

func NewSessions() *Sessions {
	return &Sessions{
		mpn: make(map[string]*User),
	}
}

func (sessions *Sessions) Set(w http.ResponseWriter, user *User) {
	sessions.mtx.Lock()
	defer sessions.mtx.Unlock()
	for k, v := range sessions.mpn {
		if v.Name == user.Name {
			delete(sessions.mpn, k)
			break
		}
	}
	key := gp.Base64Encode(gp.GenerateBytes(32))
	sessions.mpn[key] = user
	createCookie(w, key)
}

func (sessions *Sessions) Get(r *http.Request) *User {
	sessions.mtx.Lock()
	defer sessions.mtx.Unlock()
	res, ok := sessions.mpn[readCookie(r)]
	if !ok {
		return nil
	}
	return res
}

func (sessions *Sessions) Del(w http.ResponseWriter, r *http.Request) {
	sessions.mtx.Lock()
	defer sessions.mtx.Unlock()
	delete(sessions.mpn, readCookie(r))
	deleteCookie(w)
}

func createCookie(w http.ResponseWriter, data string) {
	c := http.Cookie{
		Name:   "storage",
		Value:  data,
		MaxAge: 3600,
	}
	http.SetCookie(w, &c)
}

func readCookie(r *http.Request) string {
	c, err := r.Cookie("storage")
	value := ""
	if err == nil {
		value = c.Value
	}
	return value
}

func deleteCookie(w http.ResponseWriter) {
	c := http.Cookie{
		Name:   "storage",
		MaxAge: -1,
	}
	http.SetCookie(w, &c)
}
