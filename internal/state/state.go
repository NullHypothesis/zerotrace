package state

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Amnesic-Systems/zero/internal/probe"
)

const (
	reqTimeout  = time.Second * 3
	ipidTimeout = time.Second * 10
)

type pair struct {
	req *probe.Request
	res *probe.Response
}

func (p *pair) IsAnswered() bool {
	return p.req != nil && p.res != nil
}

func (p *pair) RTT() time.Duration {
	return p.res.RecvAt.Sub(p.req.Sent)
}

// Machine represents our traceroute state machine.  We keep track of the
// following:
//  1. The IP address of the client that is the target of our traceroute.
//  2. Packets that we sent and received as part of the traceroute.
//  3. The IP IDs that we use as part of the traceroute.
type Machine struct {
	sync.Mutex // Guards ipidToPkts.
	dstAddr    net.IP
	ipidToPkts map[uint16]*pair
}

// NewMachine returns a new traceroute state machine.
func NewMachine(dstAddr net.IP) *Machine {
	return &Machine{
		dstAddr:    dstAddr,
		ipidToPkts: make(map[uint16]*pair),
	}
}

// AddTracePkt adds to the state map a trace packet.
func (s *Machine) AddProbeReq(p *probe.Request) {
	s.Lock()
	defer s.Unlock()

	// Do we already have a probe request?
	if _, exists := s.ipidToPkts[p.IPID]; exists {
		log.Printf("already have a probe request for IP ID %d", p.IPID)
		return
	}

	s.ipidToPkts[p.IPID] = &pair{
		req: p,
	}
}

// AddProbeResp adds to the state map a packet that we got in response to a
// previously-sent trace packet.
func (s *Machine) AddProbeResp(p *probe.Response) {
	s.Lock()
	defer s.Unlock()

	pkts, ok := s.ipidToPkts[p.IPID]
	if !ok {
		// when can this happen?
		log.Printf("unexpected response packet for IP ID %d", p.IPID)
		return
	}
	pkts.res = p

	// tracePkt, exists := s.ipidToPkts[p.IPID]
	// if !exists {
	// 	return
	// }
	// // Mark the trace packet as "received".
	// tracePkt.RecvAt = p.RecvAt
	// tracePkt.RecvFrom = p.RecvFrom
}

// IsDone returns `true` if the state indicates that the trace is done. That's
// the case when we haven't received any response packets since the timeout.
func (s *Machine) IsDone() bool {
	s.Lock()
	defer s.Unlock()

	now := time.Now().UTC()
	for _, p := range s.ipidToPkts {
		if p.IsAnswered() {
			continue
		}
		if now.Sub(p.req.Sent) < reqTimeout {
			return false
		}
	}
	return true
}

// String returns a human-readable summary of the traceroute's state.
func (s *Machine) String() string {
	s.Lock()
	defer s.Unlock()

	numRcvd := 0
	for _, p := range s.ipidToPkts {
		if p.IsAnswered() {
			numRcvd++
		}
	}
	return fmt.Sprintf("%d pkts sent; %d pkts received so far.",
		len(s.ipidToPkts), numRcvd)
}

// CalcRTT determines the RTT between us and the client by looking for the
// trace packet that was answered by the client itself *or* for the trace
// packet that made it the farthest to the client (i.e., the packet whose TTL
// is the highest).
func (s *Machine) CalcRTT() (time.Duration, error) {
	s.Lock()
	defer s.Unlock()

	var closest *pair
	for _, p := range s.ipidToPkts {
		if !p.IsAnswered() {
			continue
		}
		if closest == nil {
			closest = p
		}

		// If we got a response from the target itself, we're done.
		if p.res.RecvFrom.Equal(s.dstAddr) {
			log.Println("Got response packet from the target itself.")
			closest = p
			break
		}

		// If the TTL is higher, we've found a new closest packet.
		if p.req.TTL > closest.req.TTL {
			closest = p
		}

		// If the TTL is identical, pick the packet whose RTT is lower.
		if p.req.TTL == closest.req.TTL {
			if p.RTT() < closest.RTT() {
				closest = p
			}
		}
	}
	if closest != nil {
		log.Printf("Closest response packet from: %s", closest)
		return closest.RTT(), nil
	}
	return 0, errors.New("no response packets")
}
