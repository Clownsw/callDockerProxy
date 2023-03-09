package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/ishidawataru/sctp"
)

var DockerProxyPath string

const userlandProxyCommandName = "docker-proxy"

func newProxyCommand(proto string, hostIP net.IP, hostPort int, containerIP net.IP, containerPort int, proxyPath string) (userlandProxy, error) {
	path := proxyPath
	if proxyPath == "" {
		cmd, err := exec.LookPath(userlandProxyCommandName)
		if err != nil {
			return nil, err
		}
		path = cmd
	}

	args := []string{
		path,
		"-proto", proto,
		"-host-ip", hostIP.String(),
		"-host-port", strconv.Itoa(hostPort),
		"-container-ip", containerIP.String(),
		"-container-port", strconv.Itoa(containerPort),
	}

	return &proxyCommand{
		cmd: &exec.Cmd{
			Path: path,
			Args: args,
			SysProcAttr: &syscall.SysProcAttr{
				Pdeathsig: syscall.SIGTERM, // send a sigterm to the proxy if the creating thread in the daemon process dies (https://go.dev/issue/27505)
			},
		},
		wait: make(chan error, 1),
	}, nil
}

// proxyCommand wraps an exec.Cmd to run the userland TCP and UDP
// proxies as separate processes.
type proxyCommand struct {
	cmd  *exec.Cmd
	wait chan error
}

func (p *proxyCommand) Start() error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("proxy unable to open os.Pipe %s", err)
	}
	defer r.Close()
	p.cmd.ExtraFiles = []*os.File{w}

	// As p.cmd.SysProcAttr.Pdeathsig is set, the signal will be sent to the
	// process when the OS thread on which p.cmd.Start() was executed dies.
	// If the thread is allowed to be released back into the goroutine
	// thread pool, the thread could get terminated at any time if a
	// goroutine gets scheduled onto it which calls runtime.LockOSThread()
	// and exits without a matching number of runtime.UnlockOSThread()
	// calls. Ensure that the thread from which Start() is called stays
	// alive until the proxy or the daemon process exits to prevent the
	// proxy from getting terminated early. See https://go.dev/issue/27505
	// for more details.
	started := make(chan error)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := p.cmd.Start()
		started <- err
		if err != nil {
			return
		}
		p.wait <- p.cmd.Wait()
	}()
	if err := <-started; err != nil {
		return err
	}
	w.Close()

	errchan := make(chan error, 1)
	go func() {
		buf := make([]byte, 2)
		r.Read(buf)

		if string(buf) != "0\n" {
			errStr, err := io.ReadAll(r)
			if err != nil {
				errchan <- fmt.Errorf("Error reading exit status from userland proxy: %v", err)
				return
			}

			errchan <- fmt.Errorf("Error starting userland proxy: %s", errStr)
			return
		}
		errchan <- nil
	}()

	select {
	case err := <-errchan:
		return err
	case <-time.After(16 * time.Second):
		return fmt.Errorf("Timed out proxy starting the userland proxy")
	}
}

func (p *proxyCommand) Stop() error {
	if p.cmd.Process != nil {
		if err := p.cmd.Process.Signal(os.Interrupt); err != nil {
			return err
		}
		return <-p.wait
	}
	return nil
}

type userlandProxy interface {
	Start() error
	Stop() error
}

// ipVersion refers to IP version - v4 or v6
type ipVersion string

const (
	// IPv4 is version 4
	ipv4 ipVersion = "4"
	// IPv4 is version 6
	ipv6 ipVersion = "6"
)

// dummyProxy just listen on some port, it is needed to prevent accidental
// port allocations on bound port, because without userland proxy we using
// iptables rules and not net.Listen
type dummyProxy struct {
	listener  io.Closer
	addr      net.Addr
	ipVersion ipVersion
}

func NewDummyProxy(proto string, hostIP net.IP, hostPort int) (userlandProxy, error) {
	// detect version of hostIP to bind only to correct version
	version := ipv4
	if hostIP.To4() == nil {
		version = ipv6
	}
	switch proto {
	case "tcp":
		addr := &net.TCPAddr{IP: hostIP, Port: hostPort}
		return &dummyProxy{addr: addr, ipVersion: version}, nil
	case "udp":
		addr := &net.UDPAddr{IP: hostIP, Port: hostPort}
		return &dummyProxy{addr: addr, ipVersion: version}, nil
	case "sctp":
		addr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: hostIP}}, Port: hostPort}
		return &dummyProxy{addr: addr, ipVersion: version}, nil
	default:
		return nil, fmt.Errorf("Unknown addr type: %s", proto)
	}
}

func (p *dummyProxy) Start() error {
	switch addr := p.addr.(type) {
	case *net.TCPAddr:
		l, err := net.ListenTCP("tcp"+string(p.ipVersion), addr)
		if err != nil {
			return err
		}
		p.listener = l
	case *net.UDPAddr:
		l, err := net.ListenUDP("udp"+string(p.ipVersion), addr)
		if err != nil {
			return err
		}
		p.listener = l
	case *sctp.SCTPAddr:
		l, err := sctp.ListenSCTP("sctp"+string(p.ipVersion), addr)
		if err != nil {
			return err
		}
		p.listener = l
	default:
		return fmt.Errorf("Unknown addr type: %T", p.addr)
	}
	return nil
}

func (p *dummyProxy) Stop() error {
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}
func Proxy(hostip string, hostport int, containerip string, containerport int) error {
	// userlandProxy, err := NewDummyProxy("tcp", net.ParseIP("0.0.0.0"), 8888)
	userlandProxy, err := newProxyCommand("tcp", net.ParseIP(hostip), hostport, net.ParseIP(containerip), containerport, DockerProxyPath)
	if err != nil {
		return err
	}
	cleanup := func() error {
		// need to undo the iptables rules before we return
		userlandProxy.Stop()
		// pm.DeleteForwardingTableEntry(m.proto, hostIP, allocatedHostPort, containerIP.String(), containerPort)
		// if err := pm.Allocator.ReleasePort(hostIP, m.proto, allocatedHostPort); err != nil {
		//  return err
		// }

		return nil
	}

	if err := userlandProxy.Start(); err != nil {
		if err := cleanup(); err != nil {
			return fmt.Errorf("Error during port allocation cleanup: %v", err)
		}
		return err
	}
	return nil
}
