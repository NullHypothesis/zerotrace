package zero

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"

	"github.com/Amnesic-Systems/zero/internal/config"
	"github.com/Amnesic-Systems/zero/internal/ipid"
	"github.com/Amnesic-Systems/zero/internal/netx"
	"github.com/Amnesic-Systems/zero/internal/probe"
	"github.com/Amnesic-Systems/zero/internal/state"
)

var (
	l         = log.New(os.Stderr, "0trace: ", log.Ldate|log.Lmicroseconds|log.LUTC|log.Lshortfile)
	errNoIcmp = errors.New("not an ICMP packet")
)

type receiver chan *probe.Response

// Trace implements the 0trace traceroute technique:
// https://seclists.org/fulldisclosure/2007/Jan/145

type seqReq struct {
	fiveTuple netx.FiveTuple
	ch        chan netx.SequenceNumbers // chan to send back the sequence numbers
}

type Trace struct {
	register, unregister chan receiver
	rawConn              *ipv4.RawConn
	seqReq               chan seqReq
	ipids                *ipid.Pool
	pcap                 *pcap.Handle
	cfg                  *config.Config
}

// NewTrace returns a new Trace object that uses the given
// configuration.
func NewTrace(opts ...config.Option) *Trace {
	cfg := config.Default()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Trace{
		cfg:        &cfg,
		register:   make(chan receiver),
		unregister: make(chan receiver),
		ipids:      ipid.NewPool(),
	}
}

// Start starts the Trace object.  This function instructs Trace to
// start its event loop and to begin capturing network packets.
func (t *Trace) Start(ctx context.Context) (func(), error) {
	var err error
	t.rawConn, err = netx.CreateRawIpConn()
	if err != nil {
		return nil, err
	}

	t.pcap, err = netx.OpenPcap(t.cfg.Interface, t.cfg.SnapLen, t.cfg.PktBufTimeout)
	if err != nil {
		return nil, err
	}
	go t.listen(ctx, t.register, t.unregister, gopacket.NewPacketSource(
		t.pcap,
		t.pcap.LinkType(),
	).Packets())

	return func() { t.pcap.Close() }, nil
}

// CalcRTT starts a new traceroute and returns the RTT to the target
// or, if the target won't respond to us, the RTT of the hop that's closest.
// The given net.Conn represents an already-established TCP connection to the
// target. Note that the TCP connection may be corrupted as part of the 0trace
// measurement.
// TODO:
// - should take context as input
// - should say if the target itself answered or the closest hop
func (t *Trace) CalcRTT(conn net.Conn) (time.Duration, error) {
	fiveTuple, err := netx.ExtractFiveTuple(conn)
	if err != nil {
		return 0, err
	}
	seqReq := seqReq{
		fiveTuple: *fiveTuple,
		ch:        make(chan netx.SequenceNumbers, 1),
	}
	t.seqReq <- seqReq
	// Block until we get at least one other packet from the remote host,
	// allowing us to extract the sequence numbers.
	seqNums := <-seqReq.ch

	// TODO: extract sequence numbers for the five-tuple of the connection.
	// send req over channel, get back seq numbers
	sm := state.NewMachine(fiveTuple.DstIP)

	// Register for receiving a copy of newly-captured ICMP responses.
	ch := make(chan *probe.Response, 1)
	defer close(ch)
	t.register <- ch
	defer func() { t.unregister <- ch }()

	// Spawn goroutine that sends bursts of trace packets.
	wg := sync.WaitGroup{}
	wg.Add(1)
	t.sendTracePkts(sm, fiveTuple, &seqNums, &wg)

	ticker := time.NewTicker(250 * time.Millisecond) // TODO: make configurable
	for {
		select {
		case respPkt := <-ch:
			sm.AddProbeResp(respPkt) // Received new response packet.
		case <-ticker.C:
			wg.Wait()
			if sm.IsDone() {
				fmt.Println(sm)
				return sm.CalcRTT()
			}
		}
	}
}

// sendTracePkts sends a burst of trace packets to our target.  Once a packet
// was sent, it's written to the given channel.
func (t *Trace) sendTracePkts(
	sm *state.Machine,
	fiveTuple *netx.FiveTuple,
	seq *netx.SequenceNumbers,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// dstAddr, err := netx.ExtractRemoteIP(conn)
	// if err != nil {
	// 	l.Printf("Error extracting remote IP address from connection: %v", err)
	// 	return
	// }
	pktPayload, err := netx.CreatePkt(fiveTuple, seq)
	if err != nil {
		l.Printf("Error creating trace packet payload: %v", err)
		return
	}

	start := time.Now().UTC()
	defer func() {
		diff := time.Now().UTC().Sub(start)
		l.Printf("Sent trace packets in: %v", diff)
	}()
	for ttl := t.cfg.TTLStart; ttl <= t.cfg.TTLEnd; ttl++ {
		// Parallelize the sending of trace packets.
		go func(ttl int) {
			hdr := netx.NewIpv4Header(ttl, 0, fiveTuple.DstIP, len(pktPayload))
			// Send n probe packets for redundancy, in case some get lost.
			// Each probe packet shares a TTL but has a unique ID.
			for n := 0; n < t.cfg.NumProbes; n++ {
				ipID, err := t.ipids.Borrow()
				if err != nil {
					l.Printf("Error borrowing IPID: %v", err)
					continue
				}
				hdr.ID = int(ipID)
				if err = t.rawConn.WriteTo(hdr, pktPayload, nil); err != nil {
					l.Printf("Error sending trace packet: %v", err)
					continue
				}
				// Add the trace packet to the state machine.
				sm.AddProbeReq(&probe.Request{
					TTL:  uint8(ttl),
					IPID: ipID,
					Sent: time.Now().UTC(),
				})
			}
		}(ttl)
	}
}

// listen processes incoming ICMP packets that may be (but aren't always) trace
// packets.
func (t *Trace) listen(
	ctx context.Context,
	register, unregister chan receiver,
	pktStream chan gopacket.Packet,
) {
	l.Println("Starting listening loop.")
	defer l.Println("Leaving listening loop.")

	ticker := time.NewTicker(3 * time.Second) // TODO: make configurable
	chans := make(map[receiver]struct{})
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.ipids.ReleaseUnanswered()
		case r := <-register:
			chans[r] = struct{}{}
		case r := <-unregister:
			delete(chans, r)
		// case c := <-connCh:
		// Find sequence numbers for the five-tuple of the connection.
		case pkt := <-pktStream:
			// We are interested in two types of packets. First, the TCP packets
			// among which we seek to blend in.
			respPkt, err := t.parseIcmpPkt(pkt)
			if err != nil {
				l.Printf("Error parsing ICMP packet: %v", err)
				continue
			}
			t.ipids.Release(respPkt.IPID)
			// Fan-out new packet to all receivers.
			for c := range chans {
				// A receiver's channel may be full if the receiver is done with
				// the scan and has already exited its event loop.
				if len(c) == 0 { // TODO: bad
					c <- respPkt
				}
			}
		}
	}
}

// parseIcmpPkt extracts what we need (IP ID, timestamp, address) from the
// given ICMP packet.
func (t *Trace) parseIcmpPkt(packet gopacket.Packet) (*probe.Response, error) {
	if packet == nil {
		return nil, errNoIcmp
	}
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if ipv4Layer == nil || icmpLayer == nil {
		return nil, errNoIcmp
	}
	icmpPkt, _ := icmpLayer.(*layers.ICMPv4)

	ipID, err := netx.ExtractIPID(icmpPkt.LayerPayload())
	if err != nil {
		return nil, err
	}

	// We're not interested in the response packet's TTL because by definition,
	// it's always going to be 1.
	return &probe.Response{
		IPID:     ipID,
		RecvAt:   packet.Metadata().Timestamp,
		RecvFrom: ipv4Layer.SrcIP,
	}, nil
}
