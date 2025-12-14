package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"github.com/Amnesic-Systems/zero"
	"github.com/Amnesic-Systems/zero/internal/config"
)

var (
	l = log.New(os.Stderr, "example: ", log.Ldate|log.Ltime|log.LUTC|log.Lshortfile)
)

func getIdxHandler(domain, addr string) http.HandlerFunc {
	idxPage := `
<!doctype html>
<html lang="en">
  <head>
    <meta charset = "utf-8">
    <title>ZeroTrace test</title>
  </head>
  <body>
    <p>Status: <span id="status">Running</span></p>
    <script>
      function getLatencyWebSocket(endpoint) {
        return new Promise(function(resolve, reject) {
          var socket = new WebSocket(endpoint);
          socket.onerror = function (err) {
            reject(err.toString());
          }
          socket.onclose = function(event) {
            resolve();
          }
          socket.onmessage = function(event) {
            socket.send(event.data);
          }
        });
      }
      getLatencyWebSocket("wss://{{.WssEndpoint}}/wss").then(() => {
        document.getElementById("status").innerHTML = "Done.";
      });
    </script>
  </body>
</html>`
	idxTemplate := template.Must(template.New("idx").Parse(idxPage))

	return func(w http.ResponseWriter, r *http.Request) {
		s := struct {
			WssEndpoint string
		}{
			WssEndpoint: domain + addr,
		}
		if err := idxTemplate.Execute(w, s); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func getWssHandler(z *zero.Trace) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		l.Println("Handling new WebSocket request.")

		var upgrader = websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		}
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() {
			if err := c.Close(); err != nil {
				l.Printf("Error closing WebSocket conn: %v", err)
			}
		}()
		l.Println("Successfully upgraded request to WebSocket.")

		done := make(chan bool)
		// Start 0trace measurement in the background.
		go func() {
			myConn := c.UnderlyingConn()
			rtt, err := z.CalcRTT(myConn)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			l.Printf("Round trip time to client: %dms", rtt.Milliseconds())
			close(done)
		}()

		// Keep the client around while the measurement is running because we need
		// to take advantage of the already-established TCP connection.
		for {
			select {
			case <-done:
				l.Println("0trace measurement is done.")
				return
			case <-time.Tick(time.Second):
				if err := c.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
					l.Printf("Error writing message to WebSocket conn: %v", err)
				}
			}
		}
	}
}

func main() {
	var addr, domain, ifaceName string
	flag.StringVar(&ifaceName, "iface", "eth0", "Network interface name to listen on")
	flag.StringVar(&addr, "addr", ":8080", "Address to listen on")
	flag.StringVar(&domain, "domain", "", "The Web server's domain name.")
	flag.Parse()

	if domain == "" {
		l.Fatal("Specify domain name by using the -domain flag.")
	}

	z := zero.NewTrace(config.WithInterface(ifaceName))
	stopFn, err := z.Start(context.Background())
	if err != nil {
		l.Fatalf("Error starting trace: %v", err)
	}
	defer stopFn()

	router := chi.NewRouter()
	router.Get("/wss", getWssHandler(z))
	router.Get("/", getIdxHandler(domain, addr))

	// certManager := autocert.Manager{
	// 	Prompt:     autocert.AcceptTOS,
	// 	Cache:      autocert.DirCache("certs"),
	// 	HostPolicy: autocert.HostWhitelist(domain),
	// }
	// go http.ListenAndServe(":http", certManager.HTTPHandler(nil)) //nolint:errcheck
	// server := &http.Server{
	// 	Addr:    addr,
	// 	Handler: router,
	// 	// TLSConfig: &tls.Config{
	// 	// 	GetCertificate: certManager.GetCertificate,
	// 	// },
	// }
	if err := http.ListenAndServe(addr, router); err != nil {
		l.Fatalf("Error starting HTTP server: %v", err)
	}

	//l.Printf("Starting Web service to listen on %s.", addr)
	//l.Println(server.ListenAndServeTLS("", ""))
}
