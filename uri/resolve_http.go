package uri

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"

	"github.com/telehash/gogotelehash/e3x"
)

func resolveHTTP(uri *URI) (*e3x.Ident, error) {
	resp, err := http.Get("http://" + uri.Canonical + "/.well-known/mesh.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	typ := resp.Header.Get("Content-Type")
	typ, _, err = mime.ParseMediaType(typ)
	if err != nil {
		return nil, err
	}
	if typ != "application/json" && typ != "text/json" {
		return nil, fmt.Errorf("unexpected content type: %q", typ)
	}

	var ident *e3x.Ident

	err = json.NewDecoder(resp.Body).Decode(&ident)
	if err != nil {
		return nil, err
	}

	return ident, nil
}

// WellKnown returns an http.Handler which will serve the /.well-known/mesh.json
// document for Endpoint.
func WellKnown(e *e3x.Endpoint) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "GET" {
			http.NotFound(rw, req)
			return
		}
		if req.URL.Path != "/.well-known/mesh.json" {
			http.NotFound(rw, req)
			return
		}

		ident, err := e.LocalIdent()
		if err != nil {
			http.NotFound(rw, req)
			return
		}

		rw.Header().Set("Content-Type", "application/json; charset=utf-8")
		rw.WriteHeader(200)
		json.NewEncoder(rw).Encode(ident)
	})
}
