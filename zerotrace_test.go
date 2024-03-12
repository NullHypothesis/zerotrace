package zerotrace

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func makePkt(ipid uint16, srcAddr net.IP) gopacket.Packet {
	var (
		idLs = byte(ipid & 0xff)
		idMs = byte(ipid >> 8)
		adr1 = srcAddr.To4()[0]
		adr2 = srcAddr.To4()[1]
		adr3 = srcAddr.To4()[2]
		adr4 = srcAddr.To4()[3]
	)

	return gopacket.NewPacket([]byte{
		// 20-byte IP layer.
		0x45, 0xc0, 0x00, 0x50, 0x6f, 0x45, 0x00, 0x00, 0x3d, 0x01,
		0x83, 0xd0, adr1, adr2, adr3, adr4, 0xc0, 0xa8, 0x01, 0x03,
		// 60-byte ICMP layer.
		0x0b, 0x00, 0xb2, 0xee, 0x00, 0x00, 0x00, 0x00, 0x45, 0x20,
		0x00, 0x34, idMs, idLs, 0x00, 0x00, 0x01, 0x11, 0x53, 0x33,
		0xc0, 0xa8, 0x01, 0x03, 0x01, 0x01, 0x01, 0x01, 0xa2, 0xad,
		0x82, 0xa6, 0x00, 0x20, 0x1c, 0x9d, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}, layers.LayerTypeIPv4, gopacket.DecodeOptions{})
}

func TestListen(t *testing.T) {
	var (
		z         = NewZeroTrace(NewDefaultConfig())
		pktStream = make(chan gopacket.Packet)
		addr      = net.ParseIP("1.2.3.4")
		receiver  = make(receiver)
		ipid      = uint16(123)
	)

	go func() {
		z.listen(pktStream)
	}()
	defer close(z.quit)

	// Register for receiving incoming packets.
	z.incoming <- receiver
	defer func() {
		z.outgoing <- receiver
	}()
	// Pretend that there's a new incoming packet.
	pktStream <- makePkt(ipid, addr)

	respPkt := <-receiver
	fmt.Println(respPkt)
	assertEqual(t, respPkt.ipID, ipid)
}
