package netx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

const (
	// The payload that our trace packets carry.
	tcpPayload = "trace packet"
)

var (
	errInvalidIPHeader = errors.New("invalid IP header")
)

// CreatePkt creates and returns a trace packet for the given net.Conn object.
// Importantly, the function only returns the TCP header and the application
// payload.  The function assembles a TCP segment that resembles the given
// net.Conn and has a small dummy payload.  The returned byte slice is ready to
// be written to the wire when combined with an IP header.
func CreatePkt(t *FiveTuple, seq *SequenceNumbers) ([]byte, error) {
	// Extract hosts and ports from our net.Conn object.
	// srcIP, strSrcPort, err := net.SplitHostPort(conn.LocalAddr().String())
	// if err != nil {
	// 	return nil, err
	// }
	// dstIP, strDstPort, err := net.SplitHostPort(conn.RemoteAddr().String())
	// if err != nil {
	// 	return nil, err
	// }

	// // Convert ports from string to int.
	// srcPort, err := strconv.ParseUint(strSrcPort, 10, 16)
	// if err != nil {
	// 	return nil, err
	// }
	// dstPort, err := strconv.ParseUint(strDstPort, 10, 16)
	// if err != nil {
	// 	return nil, err
	// }

	// Compose the pseudo header that's necessary for computing the TCP header
	// checksum.
	ipLayer := &layers.IPv4{
		Protocol: layers.IPProtocolTCP,
		SrcIP:    t.SrcIP,
		DstIP:    t.DstIP,
		Length:   uint16(20 + 20 + len(tcpPayload)),
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(t.SrcPort),
		DstPort: layers.TCPPort(t.DstPort),
		Window:  500,
		PSH:     true,
		ACK:     true,
		Seq:     0,
		Ack:     0,
	}
	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return nil, err
	}

	// Serialize our packet.
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(
		buf,
		options,
		tcpLayer,
		gopacket.Payload([]byte(tcpPayload)),
	); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// CreateRawIpConn returns a new raw IPv4 connection.  We (ab)use
// net.ListenPacket to get a raw socket.  We only care about sending packets and
// not about receiving them, so we use ip4:89 (OSPF) to "receive" packets that
// we are unlikely to encounter.
func CreateRawIpConn() (*ipv4.RawConn, error) {
	c, err := net.ListenPacket("ip4:89", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	r, err := ipv4.NewRawConn(c)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// NewIpv4Header returns a new IPv4 header.
func NewIpv4Header(ttl, id int, dstAddr net.IP, payloadLen int) *ipv4.Header {
	return &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + 20 + payloadLen,
		ID:       id,
		TTL:      ttl,
		Protocol: 6, // TCP
		Dst:      dstAddr,
	}
}

// ExtractRemoteIP extracts the remote IP address from the given net.Conn.
func ExtractRemoteIP(c net.Conn) (net.IP, error) {
	s := c.RemoteAddr().String()
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(host), nil
}

type SequenceNumbers struct {
	Seq uint32
	Ack uint32
}

type FiveTuple struct {
	SrcIP   net.IP
	SrcPort uint16
	DstIP   net.IP
	DstPort uint16
}

var errNoFiveTuple = errors.New("failed to extract five-tuple")

func ExtractFiveTuple(c net.Conn) (*FiveTuple, error) {
	// Extract hosts and ports from our net.Conn object.
	srcIP, strSrcPort, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoFiveTuple, err)
	}
	dstIP, strDstPort, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoFiveTuple, err)
	}

	// Convert ports from string to int.
	srcPort, err := strconv.ParseUint(strSrcPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoFiveTuple, err)
	}
	dstPort, err := strconv.ParseUint(strDstPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNoFiveTuple, err)
	}

	return &FiveTuple{
		SrcIP:   net.ParseIP(srcIP),
		SrcPort: uint16(srcPort),
		DstIP:   net.ParseIP(dstIP),
		DstPort: uint16(dstPort),
	}, nil
}

// ExtractIPID parses the given IP header, extracts its IP ID, and returns it.
func ExtractIPID(ipPkt []byte) (uint16, error) {
	// At the very least, we expect an IP header.
	if len(ipPkt) < 20 {
		return 0, errInvalidIPHeader
	}

	// Try decoding the packet, to see if the header is well-formed.
	ip := layers.IPv4{}
	if err := ip.DecodeFromBytes(ipPkt, gopacket.NilDecodeFeedback); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(ipPkt[4:]), nil
}

// OpenPcap returns a new pcap handle that listens for ICMP packets.
func OpenPcap(iface string, snapLen int32, timeout time.Duration) (*pcap.Handle, error) {
	promiscuous := true
	pcapHdl, err := pcap.OpenLive(
		iface,
		snapLen,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	if err = pcapHdl.SetBPFFilter("icmp"); err != nil {
		return nil, err
	}
	return pcapHdl, nil
}
