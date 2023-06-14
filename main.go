package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/go-ping/ping"

	_ "github.com/gorilla/mux"
	"github.com/likexian/whois"
)

type ScanResult struct {
	Ports  string
	Target string
	Result string
}

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.File("templates/index.html")
	})

	e.GET("/about", func(c echo.Context) error {
		return c.File("templates/about.html")
	})

	e.GET("/services", func(c echo.Context) error {
		return c.File("templates/services.html")
	})

	// Routing Nmap Tool
	e.GET("/nmap", func(c echo.Context) error {
		return c.File("templates/nmap/nmap.html")
	})

	// Routing untuk generate Nmap
	e.POST("/scan", func(c echo.Context) error {
		target := c.FormValue("target")
		ports := "1-20000"

		fmt.Printf("Scanning ports %s on %s...\n", ports, target)

		cmd := exec.Command("nmap", "-p", ports, target)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Error executing nmap command: %s", err)
		}

		result := strings.TrimSpace(string(output))

		data := ScanResult{
			Ports:  ports,
			Target: target,
			Result: result,
		}

		tmpl := template.Must(template.ParseFiles("templates/nmap/nmap_result.html"))

		return c.HTML(http.StatusOK, renderTemplate(tmpl, data))
	})

	// Routing Whois Tool
	e.GET("/whois", func(c echo.Context) error {
		return c.File("templates/whois/whois.html")
	})

	// Routing untuk meng-handle permintaan Whois
	e.POST("/whois", func(c echo.Context) error {
		domain := c.FormValue("domain")

		whoisResult, err := whois.Whois(domain)
		if err != nil {
			if strings.Contains(err.Error(), "No such domain") {

				return c.String(http.StatusNotFound, "Domain does not exist")
			} else {
				log.Fatalf("Error retrieving whois information: %s", err)
			}
		}

		result := strings.TrimSpace(whoisResult)

		data := ScanResult{
			Result: result,
		}

		tmpl := template.Must(template.ParseFiles("templates/whois/whois_result.html"))

		return c.HTML(http.StatusOK, renderTemplate(tmpl, data))
	})

	// Routing Ping ICMP Tool
	e.GET("/ping", func(c echo.Context) error {
		return c.File("templates/icmp/ping.html")
	})

	e.POST("/pings", func(c echo.Context) error {
		// Meminta request dari host or IP Address dari Target
		target := c.FormValue("domain")

		// Ping Instance
		pinger, err := ping.NewPinger(target)
		if err != nil {
			panic(err)
		}

		pinger.Count = 3                  // jumlah packet yang akan dikirim
		pinger.Interval = time.Second     // interval antar packet
		pinger.Timeout = time.Second * 10 // total timeout operasi ping

		var packets []string

		pinger.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("Packet received from %s: icmp_seq=%d time=%v\n",
				pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packetInfo := fmt.Sprintf("Packet received from %s: icmp_seq=%d time=%v\n", pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packets = append(packets, packetInfo)
		}

		var buf bytes.Buffer
		pinger.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("Packet received from %s: icmp_seq=%d time=%v\n",
				pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packetInfo := fmt.Sprintf("Packet received from %s: icmp_seq=%d time=%v\n", pkt.IPAddr, pkt.Seq, pkt.Rtt)
			packets = append(packets, packetInfo)
		}

		pinger.OnFinish = func(stats *ping.Statistics) {
			fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
			fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
			fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
				stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
		}

		fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
		err = pinger.Run() // mulai operasi ping
		if err != nil {
			panic(err)
		}

		type PingResult struct {
			Addr        string
			PacketsSent int
			PacketsRecv int
			PacketLoss  float64
			MinRtt      time.Duration
			AvgRtt      time.Duration
			MaxRtt      time.Duration
			StdDevRtt   time.Duration
			Result      string
			Packets     []string
		}

		data := PingResult{
			Addr:        pinger.Addr(),
			PacketsSent: 3,
			PacketsRecv: 3,
			PacketLoss:  0,
			MinRtt:      pinger.Statistics().MinRtt,
			AvgRtt:      pinger.Statistics().AvgRtt,
			MaxRtt:      pinger.Statistics().MaxRtt,
			StdDevRtt:   pinger.Statistics().StdDevRtt,
			Result:      buf.String(),
			Packets:     packets,
		}

		tmpl := template.Must(template.ParseFiles("templates/icmp/ping_result.html"))
		pings := data
		return c.HTML(http.StatusOK, renderTemplate(tmpl, pings))
	})

	// Routing Shodan Tool
	e.GET("/shodan", func(c echo.Context) error {
		return c.File("templates/shodan/shodan.html")
	})

	e.POST("/shodanResults", func(c echo.Context) error {
		target := c.FormValue("target")

		type shodanSearchResponse struct {
			IP        int      `json:"ip"`
			Hostnames []string `json:"hostnames"`
			OpenPorts []string `json:"ports"`
		}

		url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=(Your Shodan Keys)", target)

		response, err := http.Get(url)

		if err != nil {
			// handle error
			return err
		}

		// Membaca Body Response
		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}

		var shodanRes shodanSearchResponse
		err = json.Unmarshal(body, &shodanRes)
		if err != nil {
			return err
		}

		tmpl := template.Must(template.ParseFiles("templates/shodan/shodan_result.html"))
		return c.HTML(http.StatusOK, renderTemplate(tmpl, shodanRes))
	})

	e.Logger.Fatal(e.Start(":5000"))
}

func renderTemplate(tmpl *template.Template, data interface{}) string {
	var buf strings.Builder

	err := tmpl.Execute(&buf, data)
	if err != nil {
		log.Fatalf("Error rendering template: %s", err)
	}

	return buf.String()
}
