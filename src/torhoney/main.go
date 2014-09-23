// torhoney: small program to downloaded the list of TOR exit nodes and
// classify them using Project Honeypot
//
// Copyright (c) 2014 John Graham-Cumming

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Project Honeypot classification of an IP
//
// Details of the Project Honeypot API...
//
// FAQ: http://www.projecthoneypot.org/faq.php#g
// API: http://www.projecthoneypot.org/httpbl_api.php

type honeyClass uint8

const (
	CLASS_SUSPICIOUS honeyClass = 1
	CLASS_HARVESTER  honeyClass = 2
	CLASS_SPAMMER    honeyClass = 4
)

// Implementation of Stringer interface for honeyClass for CSV printing
func (h honeyClass) String() string {
	if h == 0 {
		return ",,"
	}
	s := ""
	if h&CLASS_SUSPICIOUS != 0 {
		s += "suspicious"
	}
	s += ","
	if h&CLASS_HARVESTER != 0 {
		s += "harvester"
	}
	s += ","
	if h&CLASS_SPAMMER != 0 {
		s += "comment spammer"
	}
	return s
}

type ipData struct {
	ip     net.IP     // The IP address this structure refers to
	err    error      // Set if lookup error occurred
	listed bool       // Whether listed by Project Honeypot
	score  uint8      // The Project Honeypot score
	days   uint8      // The number of days since Project Honeypot saw this
					  // address
	class  honeyClass // The classification of this IP
}

// resolver runs as a goroutine and accepts IP address on in, looks them up
// and parses the response into an ipData
func resolver(in chan net.IP, out chan ipData, wg *sync.WaitGroup, key string) {
	for ip := range in {
		d := ipData{ip: ip}
		addr := fmt.Sprintf("%s.%d.%d.%d.%d.dnsbl.httpbl.org", key,
			ip[3], ip[2], ip[1], ip[0])
		var ips []net.IP
		ips, d.err = net.LookupIP(addr)
		if d.err == nil {
			if ips == nil || len(ips) == 0 {
				d.listed = false
			} else {
				d.listed = true
				ips[0] = ips[0].To4()
				d.days = ips[0][1]
				d.score = ips[0][2]
				d.class = honeyClass(ips[0][3])
			}
		}

		out <- d
	}
	wg.Done()
}

func main() {
	key := flag.String("key", "", "Project Honeypot API key")
	exits := flag.String("exits",
		"https://check.torproject.org/exit-addresses",
		"TOR Project exit node list")
	workers := flag.Int("workers", 10, "Number of resolver workers to run")
	flag.Parse()

	if *key == "" {
		flag.PrintDefaults()
		return
	}

	// The TOR exit node list has entries like this:
	//
	// ExitNode 0017413E0BD04C427F79B51360031EC95043C012
	// Published 2014-09-22 15:12:27
	// LastStatus 2014-09-22 17:03:03
	// ExitAddress 105.237.199.197 2014-09-22 16:03:36
	//
	// Just parse out the ExitAddress

	resp, err := http.Get(*exits)
	if err != nil {
		log.Fatalf("Failed to get TOR exit node list %s: %s",
			*exits, err)
	}

	exitNodes := make([]net.IP, 0)

	defer resp.Body.Close()
	scan := bufio.NewScanner(resp.Body)
	for scan.Scan() {
		l := scan.Text()
		if strings.HasPrefix(l, "ExitAddress ") {
			parts := strings.Split(l, " ")
			if len(parts) < 2 {
				log.Printf("Bad ExitAddress line %s", l)
				continue
			}

			addr := net.ParseIP(parts[1])
			if addr == nil {
				log.Printf("Error parsing IP address %s", parts[1])
				continue
			}
			addr = addr.To4()
			if addr == nil {
				log.Printf("IP address %s is not v4", parts[1])
				continue
			}

			exitNodes = append(exitNodes, addr)
		}
	}

	log.Printf("Loaded %d exit nodes", len(exitNodes))

	in := make(chan net.IP)
	out := make(chan ipData)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go resolver(in, out, &wg, *key)
	}

	wg.Add(1)
	go func() {
		for _, addr := range exitNodes {
			in <- addr
		}
		close(in)
		wg.Done()
	}()

	for i := 0; i < len(exitNodes); i++ {
		d := <-out
		fmt.Printf("%s,", d.ip)

		if d.err != nil || !d.listed {
			fmt.Printf(",,\n")
			continue
		}

		fmt.Printf("%d,%d,%s\n", d.days, d.score, d.class)
	}

	wg.Wait()
	close(out)
}
