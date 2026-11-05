// Package tun captures all traffic of the system through a TUN device and
// hands each TCP connection and UDP flow to a Handler. A userspace TCP/IP
// stack (gVisor netstack) terminates the connections.
package tun

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Handler receives connections captured from the TUN device.
type Handler interface {
	// HandleTCP is called for every new TCP connection; dst is the address
	// the application connected to.
	HandleTCP(conn net.Conn, dst netip.AddrPort)
	// HandleUDP is called for every new UDP flow (src, dst). conn reads
	// datagrams sent by the application and writes replies back to it.
	HandleUDP(conn net.Conn, src, dst netip.AddrPort)
}

const (
	nicID = 1
	// Leave room in front of packets for the virtio header used by the Linux
	// TUN driver with offloads (wireguard-go needs it on writes).
	packetOffset = 16
)

// Stack bridges a TUN device and a gVisor network stack.
type Stack struct {
	dev    wgtun.Device
	ep     *channel.Endpoint
	stack  *stack.Stack
	cancel context.CancelFunc
	done   chan struct{}
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// NewStack starts forwarding packets between dev and the handler.
func NewStack(dev wgtun.Device, mtu int, h Handler) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        false,
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	// Accept packets for any destination and answer from any source.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 256 << 10, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	tcpFwd := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		ep.SocketOptions().SetKeepAlive(true)
		go h.HandleTCP(gonet.NewTCPConn(&wq, ep), addrPort(id.LocalAddress, id.LocalPort))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			return
		}
		go h.HandleUDP(gonet.NewUDPConn(&wq, ep),
			addrPort(id.RemoteAddress, id.RemotePort), addrPort(id.LocalAddress, id.LocalPort))
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{dev: dev, ep: ep, stack: s, cancel: cancel, done: make(chan struct{})}
	go st.deviceToStack()
	go st.stackToDevice(ctx)
	return st, nil
}

// deviceToStack reads packets from the TUN device and injects them.
func (st *Stack) deviceToStack() {
	defer close(st.done)
	batch := st.dev.BatchSize()
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, packetOffset+65535)
	}
	sizes := make([]int, batch)
	for {
		n, err := st.dev.Read(bufs, sizes, packetOffset)
		if err != nil {
			if errors.Is(err, wgtun.ErrTooManySegments) {
				continue
			}
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
				slog.Debug("tun read stopped", "err", err)
			}
			return
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][packetOffset : packetOffset+sizes[i]]
			if len(pkt) == 0 {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			switch pkt[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
			})
			st.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// stackToDevice writes packets produced by the stack to the TUN device.
func (st *Stack) stackToDevice(ctx context.Context) {
	for {
		pb := st.ep.ReadContext(ctx)
		if pb == nil {
			return
		}
		view := pb.ToView()
		buf := make([]byte, packetOffset+view.Size())
		copy(buf[packetOffset:], view.AsSlice())
		view.Release()
		pb.DecRef()
		if _, err := st.dev.Write([][]byte{buf}, packetOffset); err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			slog.Debug("tun write failed", "err", err)
		}
	}
}

// Close stops the stack. The device is closed by its owner.
func (st *Stack) Close() {
	st.cancel()
	st.stack.Close()
	st.ep.Close()
}
