// Command app is the service this repository ships. It is deliberately small: the point of the
// repository is everything that happens between this source and a running pod.
package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"
)

// Version is what the service reports about its own build.
type Version struct {
	Module   string `json:"module"`
	Go       string `json:"go"`
	Revision string `json:"revision,omitempty"`
	Modified bool   `json:"modified"`
}

func version() Version {
	v := Version{}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}
	v.Module, v.Go = info.Main.Path, info.GoVersion
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			v.Revision = s.Value
		case "vcs.modified":
			v.Modified = s.Value == "true"
		}
	}
	return v
}

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(version())
	})
	return mux
}

func main() {
	addr := ":8080"
	if a := os.Getenv("ADDR"); a != "" {
		addr = a
	}
	srv := &http.Server{Addr: addr, Handler: handler(), ReadHeaderTimeout: 5 * time.Second}
	slog.Info("listening", "addr", addr, "revision", version().Revision)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
