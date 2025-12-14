package netx

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	srcAddr = "10.0.0.1"
	dstAddr = "10.0.0.2"
	srcPort = 12345
	dstPort = 8080
)

// mockConn mocks a TCP connection by overriding the RemoteAddr and LocalAddr
// functions because that's all that the createPkt function needs.
type mockConn struct {
	net.TCPConn
}

func (m *mockConn) createAddr(strAddr string) net.Addr {
	addr, err := net.ResolveTCPAddr("tcp", strAddr)
	if err != nil {
		panic(err)
	}
	return addr
}

func (m *mockConn) RemoteAddr() net.Addr {
	return m.createAddr(fmt.Sprintf("%s:%d", dstAddr, dstPort))
}
func (m *mockConn) LocalAddr() net.Addr {
	return m.createAddr(fmt.Sprintf("%s:%d", srcAddr, srcPort))
}

func TestCreatePkt(t *testing.T) {
	conn := &mockConn{}
	rawPkt, err := CreatePkt(conn)
	if err != nil {
		t.Fatalf("Failed to create packet for given conn: %v", err)
	}
	pkt := gopacket.NewPacket(rawPkt, layers.LayerTypeTCP, gopacket.Default)

	// Verify payload.
	if pkt.ApplicationLayer() == nil {
		t.Fatal("no app layer")
	}
	seen := pkt.ApplicationLayer().Payload()
	expected := []byte(tcpPayload)
	if !bytes.Equal(expected, seen) {
		t.Fatalf("Expected payload %q but got %q.", expected, seen)
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer.SrcPort != srcPort {
		t.Fatalf("Expected src port %d but got %d.", srcPort, tcpLayer.SrcPort)
	}
	if tcpLayer.DstPort != dstPort {
		t.Fatalf("Expected dst port %d but got %d.", dstPort, tcpLayer.DstPort)
	}

	// Verify TCP flags.
	if tcpLayer.FIN == true ||
		tcpLayer.SYN == true ||
		tcpLayer.RST == true ||
		tcpLayer.URG == true ||
		tcpLayer.ECE == true ||
		tcpLayer.CWR == true ||
		tcpLayer.NS == true {
		t.Fatal("Expected all TCP flags except PSH and ACK to be unset.")
	}
	if tcpLayer.PSH == false || tcpLayer.ACK == false {
		t.Fatal("Expected TCP flags PSH and ACK to be set.")
	}
}

func TestExtractRemoteIP(t *testing.T) {
	c := &mockConn{}
	ip, err := ExtractRemoteIP(c)
	if err != nil {
		t.Fatalf("Expected no error but got: %v", err)
	}

	if ip.String() != dstAddr {
		t.Fatalf("Expected IP address %s but got %s.", dstAddr, ip.String())
	}
}

func TestInvalidExtractIPID(t *testing.T) {
	ipHdr := []byte{0x00}
	_, err := ExtractIPID(ipHdr)
	if !errors.Is(err, errInvalidIPHeader) {
		t.Fatalf("Expected error %v but got %v.", errInvalidIPHeader, err)
	}
}

func TestExtractIPID(t *testing.T) {
	// The "payload" of an ICMP packet, which is the 20-byte IP header of the
	// original IP packet that resulted in the ICMP error response.
	ipHdr := []byte{
		0x45, 0x20, 0x00, 0x3c, 0x19, 0x97, 0x00, 0x00, 0x00, 0x11,
		0xcf, 0x35, 0xc0, 0xa8, 0x01, 0x0d, 0x08, 0x08, 0x08, 0x08,
	}
	expectedIPID := uint16(0x1997)

	ipID, err := ExtractIPID(ipHdr)
	if err != nil {
		t.Fatalf("Failed to extract IP ID from ICMP packet: %v", err)
	}

	if ipID != expectedIPID {
		t.Fatalf("Expected IP ID %d but got %d.", expectedIPID, ipID)
	}
}
