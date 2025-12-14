package state

import (
	"net"
	"testing"
	"time"

	"github.com/Amnesic-Systems/zero/internal/probe"
)

var (
	dummyAddr = net.ParseIP("1.2.3.4")
)

func failOnErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}
}

func TestIsAnswered(t *testing.T) {
	p := &probe.Request{}

	if p.IsAnswered() {
		t.Fatal("Expected empty trace packet to be un-answered.")
	}

	now := time.Now().UTC()
	p.Sent = now
	p.RecvAt = now
	if !p.IsAnswered() {
		t.Fatal("Expected answered trace packet to be answered.")
	}
}

func TestNewTrState(t *testing.T) {
	s := NewMachine(dummyAddr)
	if s.ipidToPkts == nil {
		t.Fatal("Map in Machine struct uninitialized.")
	}
}

func TestAddTracePkt(t *testing.T) {
	s := NewMachine(dummyAddr)

	s.AddProbeReq(&probe.Request{
		TTL:  1,
		IPID: 1,
		Sent: time.Now().UTC(),
	})
	expected := 1
	if len(s.ipidToPkts) != expected {
		t.Fatalf("Expected %d recorded packets but got %d.",
			expected, len(s.ipidToPkts))
	}
}

func TestIsFinished(t *testing.T) {
	s := NewMachine(dummyAddr)
	now := time.Now().UTC()
	p := &probe.Request{
		TTL:  1,
		IPID: 1,
		Sent: now,
	}

	s.AddProbeReq(p)
	if s.IsDone() {
		t.Fatal("Expected traceroute to be unfinished.")
	}

	p.Sent = now.Add(-reqTimeout)
	if !s.IsDone() {
		t.Fatal("Expected traceroute to be finished.")
	}

	p.RecvAt = now
	if !s.IsDone() {
		t.Fatal("Expected traceroute to be finished.")
	}
}

func TestSummary(t *testing.T) {
	s := NewMachine(dummyAddr)
	if len(s.String()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}

	now := time.Now().UTC()
	s.AddProbeReq(&probe.Request{
		IPID: 1,
		TTL:  1,
		Sent: now,
	})
	if len(s.String()) == 0 {
		t.Fatal("Expected string summary of traceroute.")
	}
}

func TestCalcRTT(t *testing.T) {
	var (
		err error
		rtt time.Duration
		s   = NewMachine(dummyAddr)
		now = time.Now().UTC()
	)

	expectedRTT := time.Second
	s.AddProbeReq(&probe.Request{
		TTL:  1,
		IPID: 1,
		Sent: now.Add(-expectedRTT),
	})
	rtt, err = s.CalcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a trace packet with an identical TTL but a lower RTT.
	expectedRTT = time.Millisecond * 500
	s.AddProbeReq(&probe.Request{
		TTL:  1,
		IPID: 2,
		Sent: now.Add(-expectedRTT),
	})
	rtt, err = s.CalcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a trace packet with a higher TTL (i.e., it got closer to the
	// target).
	expectedRTT = time.Second * 2
	s.AddProbeReq(&probe.Request{
		TTL:  2,
		IPID: 2,
		Sent: now.Add(-expectedRTT),
	})
	rtt, err = s.CalcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add an unanswered packet and make sure that it doesn't affect the RTT.
	s.AddProbeReq(&probe.Request{
		TTL:  3,
		IPID: 3,
		Sent: now.Add(-time.Second * 10),
	})
	rtt, err = s.CalcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}

	// Add a packet whose TTL is lower than the existing ones but it got
	// answered by the destination itself, so it should be used to calculate
	// the RTT.
	expectedRTT = time.Second * 3
	s.AddProbeReq(&probe.Request{
		TTL:  1,
		IPID: 4,
		Sent: now.Add(-expectedRTT),
	})
	rtt, err = s.CalcRTT()
	failOnErr(t, err)
	if rtt != expectedRTT {
		t.Fatalf("Expected RTT to be %s but got %s.", expectedRTT, rtt)
	}
}
