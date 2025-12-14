package probe

import (
	"net"
	"time"
)

type Request struct {
	TTL  uint8
	IPID uint16
	Sent time.Time
}

type Response struct {
	IPID     uint16
	RecvAt   time.Time
	RecvFrom net.IP
}
