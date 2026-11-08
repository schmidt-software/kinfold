package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

const usage = `kinfold - experimental self-hosted IPv4/IPv6 VPN

Commands:
  init         Create controller state and a private CA
  add-peer     Authorize a peer and write its private credential
  keygen       Generate a private key and signed enrollment request locally
  approve      Approve an enrollment request on the controller
  rotate-peer  Replace a peer's certificate using a new local key
  export-ca    Export the controller CA certificate
  enroll       Assemble a credential using the local key and trusted CA
  remove-peer  Remove a peer
  policy-enable Add the policy section to a pre-policy state file
  allow        Allow packets in one direction between peers
  deny         Remove a directional allow rule
  service-enable Enable experimental default-deny service filtering
  service-apply Atomically replace experimental service rules from JSON
  service-allow Allow a protocol and destination port in one direction
  service-deny Remove a directional service rule
  ipv6-network Configure the optional IPv6 ULA /64 network
  ipv6-assign  Assign or remove a peer's IPv6 address
  renew-server Renew controller server certificate and key
  serve        Run the controller and encrypted relay
  status       Show the authorized network configuration
  check-config Compare the on-disk and loaded controller configuration
  run          Run the Linux TUN client
  version      Show build information

Run a command with -h for its options.
`

func flags(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ContinueOnError) }

func Run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}
	switch args[0] {
	case "renew-server":
		f := flags("renew-server")
		dir := f.String("data", "controller-data", "controller data directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		lock, err := core.LockState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		s, err := core.LoadStateForOfflineMaintenance(*dir)
		if err != nil {
			return err
		}
		if err := s.RenewServerCertificate(); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Controller certificate and key renewed on disk; restart the controller to restore service.")
		return nil
	case "ipv6-network":
		f := flags("ipv6-network")
		dir := f.String("data", "controller-data", "controller data directory")
		network := f.String("network", "", "IPv6 ULA /64 prefix, or 'none' to disable")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *network == "" {
			return fmt.Errorf("-network is required")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if *network == "none" {
			s.Config.Network6 = ""
		} else if prefix, err := netip.ParsePrefix(*network); err == nil && prefix == prefix.Masked() {
			s.Config.Network6 = prefix.String() // canonical spelling; non-masked input is rejected by Validate
		} else {
			s.Config.Network6 = *network
		}
		if err := s.Config.Validate(); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("IPv6 network updated; controller and current clients reload asynchronously.")
		return nil
	case "ipv6-assign":
		f := flags("ipv6-assign")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "peer ID")
		address := f.String("ip", "", "IPv6 address, or 'none' to remove")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *address == "" {
			return fmt.Errorf("-id and -ip are required")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		found := false
		for i := range s.Config.Peers {
			if s.Config.Peers[i].ID == *id {
				found = true
				if *address == "none" {
					s.Config.Peers[i].IPv6 = ""
				} else if ip, err := netip.ParseAddr(*address); err == nil {
					s.Config.Peers[i].IPv6 = ip.String()
				} else {
					s.Config.Peers[i].IPv6 = *address
				}
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown peer %q", *id)
		}
		if err := s.Config.Validate(); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Peer IPv6 assignment updated; controller and current clients reload asynchronously.")
		return nil
	case "check-config":
		f := flags("check-config")
		dir := f.String("data", "controller-data", "controller data directory")
		path := f.String("credential", "", "authorized peer credential file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *path == "" {
			return fmt.Errorf("-credential is required")
		}
		if err := core.CheckPrivate(*path); err != nil {
			return err
		}
		local, err := core.LoadState(*dir)
		if err != nil {
			return err
		}
		var cred core.Credential
		if err := core.ReadJSON(*path, &cred); err != nil {
			return err
		}
		if cred.Server != local.Server {
			return fmt.Errorf("credential controller address does not match local state")
		}
		if !bytes.Equal(cred.CA, local.CA) {
			return fmt.Errorf("credential CA does not match local controller state")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		remote, _, err := agent.FetchConfig(ctx, cred)
		if err != nil {
			return err
		}
		localRevision, err := local.Config.Revision()
		if err != nil {
			return err
		}
		remoteRevision, err := remote.Revision()
		if err != nil {
			return err
		}
		fmt.Printf("On-disk configuration: %s\nController configuration: %s\n", localRevision, remoteRevision)
		if localRevision != remoteRevision {
			return fmt.Errorf("controller has not loaded the on-disk configuration")
		}
		fmt.Println("Controller configuration matches the local snapshot; client convergence is not verified.")
		return nil
	case "service-apply":
		f := flags("service-apply")
		dir := f.String("data", "controller-data", "controller data directory")
		path := f.String("rules", "", "JSON file containing the complete service policy")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *path == "" {
			return fmt.Errorf("-rules is required")
		}
		input, err := os.Open(*path)
		if err != nil {
			return fmt.Errorf("open service policy: %w", err)
		}
		var policy *core.ServicePolicy
		decodeErr := core.DecodeJSON(input, &policy)
		closeErr := input.Close()
		if decodeErr != nil {
			return fmt.Errorf("decode service policy: %w", decodeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close service policy: %w", closeErr)
		}
		if policy == nil || policy.Allowed == nil {
			return fmt.Errorf("service policy must contain an allowed array; use an empty array to deny all services")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if s.Config.Policy == nil {
			return fmt.Errorf("enable default-deny policy first")
		}
		s.Config.Policy.Services = policy
		if err := s.Config.Validate(); err != nil {
			return fmt.Errorf("invalid service policy: %w", err)
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Printf("Applied %d service rules atomically on disk; controller and current clients reload asynchronously.\n", len(policy.Allowed))
		return nil
	case "service-enable":
		f := flags("service-enable")
		dir := f.String("data", "controller-data", "controller data directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if s.Config.Policy == nil {
			return fmt.Errorf("enable default-deny policy first")
		}
		if s.Config.Policy.Services != nil {
			return fmt.Errorf("service policy already enabled")
		}
		s.Config.Policy.Services = &core.ServicePolicy{}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Service default-deny enabled; controller and current clients reload asynchronously.")
		return nil
	case "service-allow", "service-deny":
		f := flags(args[0])
		dir := f.String("data", "controller-data", "controller data directory")
		from := f.String("from", "", "source peer ID")
		to := f.String("to", "", "destination peer ID")
		protocol := f.String("protocol", "", "tcp, udp, icmp or icmp6")
		port := f.Uint("port", 0, "destination port for tcp or udp")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *port > 65535 {
			return fmt.Errorf("port must be at most 65535")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := s.Config.SetServiceRule(*from, *to, *protocol, uint16(*port), args[0] == "service-allow"); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Service policy updated; controller and current clients reload asynchronously.")
		return nil
	case "policy-enable":
		f := flags("policy-enable")
		dir := f.String("data", "controller-data", "controller data directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if s.Config.Policy != nil {
			return fmt.Errorf("default-deny policy already enabled")
		}
		s.Config.Policy = &core.Policy{}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Default-deny enabled with no allow rules. Controller and updated clients reload asynchronously.")
		return nil
	case "allow", "deny":
		f := flags(args[0])
		dir := f.String("data", "controller-data", "controller data directory")
		from := f.String("from", "", "source peer ID")
		to := f.String("to", "", "destination peer ID")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		if err := s.Config.SetRule(*from, *to, args[0] == "allow"); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Printf("Updated %s -> %s. Controller and updated clients reload asynchronously.\n", *from, *to)
		return nil
	case "keygen":
		f := flags("keygen")
		id := f.String("id", "", "device ID")
		keyPath := f.String("key", "", "new private key file")
		requestPath := f.String("request", "", "new enrollment request file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *keyPath == "" || *requestPath == "" || *keyPath == *requestPath {
			return fmt.Errorf("-id, -key and distinct -request are required")
		}
		key, request, err := core.NewEnrollment(*id)
		if err != nil {
			return err
		}
		if err := writeNew(*keyPath, key); err != nil {
			return err
		}
		if err := writeNew(*requestPath, request); err != nil {
			return fmt.Errorf("private key saved to %s; request creation failed and the request file may exist: %w", *keyPath, err)
		}
		fmt.Printf("Created local private key %s and enrollment request %s. Never transfer the private key.\n", *keyPath, *requestPath)
		return nil
	case "approve", "rotate-peer":
		f := flags(args[0])
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "approved device ID")
		ip := f.String("ip", "", "approved IPv4 address")
		requestPath := f.String("request", "", "device enrollment request")
		out := f.String("out", "", "new signed certificate file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *requestPath == "" || *out == "" || (args[0] == "approve" && *ip == "") {
			return fmt.Errorf("-id, -request and -out are required; approve also requires -ip")
		}
		if args[0] == "rotate-peer" && *ip != "" {
			return fmt.Errorf("rotate-peer preserves the existing address; do not specify -ip")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		request, err := readEnrollmentFile(*requestPath)
		if err != nil {
			return err
		}
		var cert []byte
		if args[0] == "approve" {
			cert, err = s.ApproveEnrollment(*id, *ip, request)
		} else {
			cert, err = s.RotatePeerEnrollment(*id, request)
		}
		if err != nil {
			return err
		}
		if err := writeNew(*out, cert); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return fmt.Errorf("certificate written to %s; controller state update failed or its durability is uncertain: %w", *out, err)
		}
		fmt.Printf("Updated %s. Transfer %s back securely; controller and current clients reload asynchronously.\n", *id, *out)
		return nil
	case "export-ca":
		f := flags("export-ca")
		dir := f.String("data", "controller-data", "controller data directory")
		out := f.String("out", "", "new public CA certificate file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *out == "" {
			return fmt.Errorf("-out is required")
		}
		s, err := core.LoadState(*dir)
		if err != nil {
			return err
		}
		if err := writeNew(*out, s.CA); err != nil {
			return err
		}
		fmt.Println("Exported CA. Verify its fingerprint through an independent trusted channel.")
		return nil
	case "enroll":
		f := flags("enroll")
		server := f.String("server", "", "controller host:port")
		keyPath := f.String("key", "", "local private key file")
		certPath := f.String("cert", "", "approved certificate file")
		caPath := f.String("ca", "", "independently verified CA certificate file")
		out := f.String("out", "", "new private credential file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *server == "" || *keyPath == "" || *certPath == "" || *caPath == "" || *out == "" {
			return fmt.Errorf("-server, -key, -cert, -ca and -out are required")
		}
		if err := core.CheckPrivate(*keyPath); err != nil {
			return err
		}
		key, err := readEnrollmentFile(*keyPath)
		if err != nil {
			return err
		}
		cert, err := readEnrollmentFile(*certPath)
		if err != nil {
			return err
		}
		ca, err := readEnrollmentFile(*caPath)
		if err != nil {
			return err
		}
		cred, err := core.CompleteEnrollment(*server, ca, cert, key)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*out, append(data, '\n')); err != nil {
			return err
		}
		fmt.Printf("Created private credential %s. Keep it and %s confidential.\n", *out, *keyPath)
		return nil
	case "init":
		f := flags("init")
		dir := f.String("data", "controller-data", "new controller data directory")
		server := f.String("server", "", "public controller host:port used by clients")
		network := f.String("network", "10.77.0.0/24", "canonical IPv4 network")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *server == "" {
			return fmt.Errorf("-server is required")
		}
		if err := core.InitState(*dir, *server, *network); err != nil {
			return err
		}
		fmt.Printf("Created controller state in %s. Keep it secret and back it up.\n", *dir)
		return nil
	case "add-peer":
		f := flags("add-peer")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "unique peer ID")
		ip := f.String("ip", "", "peer IPv4 address")
		out := f.String("out", "", "new credential file (transfer securely)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *ip == "" || *out == "" {
			return fmt.Errorf("-id, -ip and -out are required")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		cred, err := s.AddPeer(*id, *ip)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*out, append(data, '\n')); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return fmt.Errorf("credential written to %s; controller state update failed or its durability is uncertain: %w", *out, err)
		}
		fmt.Printf("Authorized %s. Transfer %s securely; updated clients reload asynchronously.\n", *id, *out)
		return nil
	case "remove-peer":
		f := flags("remove-peer")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "peer ID to revoke")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		lock, err := core.LockState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		s, err := core.LoadStateForOfflineMaintenance(*dir)
		if err != nil {
			return err
		}
		if _, ok := s.Config.Peer(*id); !ok {
			return fmt.Errorf("unknown peer %q", *id)
		}
		if err := s.RememberActivePeerKeys(); err != nil {
			return err
		}
		var peers []core.Peer
		for _, p := range s.Config.Peers {
			if p.ID != *id {
				peers = append(peers, p)
			}
		}
		s.Config.Peers = peers
		if s.Config.Policy != nil {
			rules := s.Config.Policy.Allowed[:0]
			for _, rule := range s.Config.Policy.Allowed {
				if rule.From != *id && rule.To != *id {
					rules = append(rules, rule)
				}
			}
			s.Config.Policy.Allowed = rules
			if s.Config.Policy.Services != nil {
				rules := s.Config.Policy.Services.Allowed[:0]
				for _, rule := range s.Config.Policy.Services.Allowed {
					if rule.From != *id && rule.To != *id {
						rules = append(rules, rule)
					}
				}
				s.Config.Policy.Services.Allowed = rules
			}
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Println("Peer removed from disk. Controller and updated clients reload asynchronously; CLI does not confirm enforcement.")
		return nil
	case "serve":
		f := flags("serve")
		dir := f.String("data", "controller-data", "controller data directory")
		listen := f.String("listen", ":8443", "TCP listen address")
		maxConns := f.Int("max-conns", relay.DefaultListenerLimits.Total, "maximum concurrent TCP connections")
		maxPerIP := f.Int("max-conns-per-ip", relay.DefaultListenerLimits.PerSource, "maximum concurrent TCP connections per source IP (0 disables)")
		ratePerIP := f.Float64("conn-rate-per-ip", relay.DefaultListenerLimits.RatePerSource, "new TCP connections per second per source IP (0 disables)")
		logging := addLogFlags(f)
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if err := logging.configure(); err != nil {
			return err
		}
		s, err := core.LoadState(*dir)
		if err != nil {
			return err
		}
		if s.Config.Policy == nil {
			return fmt.Errorf("state has no policy section (pre-policy format); run 'kinfold policy-enable -data %s' and add allow rules before serving", *dir)
		}
		handler, err := relay.New(s.Config)
		if err != nil {
			return err
		}
		tlsCfg, err := relay.TLSConfig(s)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		limits := relay.ListenerLimits{Total: *maxConns, PerSource: *maxPerIP, RatePerSource: *ratePerIP, BurstPerSource: max(*maxPerIP, 1)}
		ln, err := listenController(ctx, *listen, limits)
		if err != nil {
			return err
		}
		server := newControllerServer(handler, tlsCfg, defaultServerTimeouts)
		for _, warning := range s.CertificateWarnings(time.Now(), 30*24*time.Hour) {
			slog.Warn(warning)
		}
		slog.Info("controller listening", "address", ln.Addr().String(), "build", readBuildInfo().short(), "peers", len(s.Config.Peers))
		return serveController(ctx, server, ln, handler, func(ctx context.Context) {
			handler.Watch(ctx.Done(), s, func() (*core.State, error) { return core.LoadState(*dir) }, time.Second)
		}, 5*time.Second)
	case "status", "run":
		f := flags(args[0])
		path := f.String("credential", "", "private peer credential file")
		iface := f.String("interface", "kf0", "new Linux TUN interface name")
		logging := addLogFlags(f)
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *path == "" {
			return fmt.Errorf("-credential is required")
		}
		if args[0] == "run" {
			if err := logging.configure(); err != nil {
				return err
			}
		}
		if err := core.CheckPrivate(*path); err != nil {
			return err
		}
		var cred core.Credential
		if err := core.ReadJSON(*path, &cred); err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		cfg, id, err := agent.FetchConfig(ctx, cred)
		if err != nil {
			return err
		}
		self, _ := cfg.Peer(id)
		fmt.Printf("Peer %s (%s), network %s, %d authorized peers\n", id, self.IP, cfg.Network, len(cfg.Peers))
		if cfg.Network6 != "" {
			fmt.Printf("IPv6 network %s, local address %s\n", cfg.Network6, self.IPv6)
		}
		if cfg.Policy == nil {
			if args[0] == "run" {
				slog.Warn("configuration has no policy; all peer traffic is denied")
			} else {
				fmt.Fprintln(os.Stderr, "WARNING: configuration has no policy; all peer traffic is denied.")
			}
		} else {
			fmt.Printf("Static default-deny policy: %d directional allow rules\n", len(cfg.Policy.Allowed))
			if cfg.Policy.Services != nil {
				fmt.Printf("Experimental service default-deny: %d directional service rules\n", len(cfg.Policy.Services.Allowed))
			}
		}
		if args[0] == "status" {
			for _, p := range cfg.Peers {
				if p.IPv6 == "" {
					fmt.Printf("  %s  %s\n", p.ID, p.IP)
				} else {
					fmt.Printf("  %s  %s  %s\n", p.ID, p.IP, p.IPv6)
				}
			}
			return nil
		}
		slog.Info("client starting", "peer", id, "build", readBuildInfo().short())
		return runSupervised(ctx, cred, cfg, id, *iface)
	case "version":
		f := flags("version")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		printVersion(os.Stdout, readBuildInfo())
		return nil
	default:
		return fmt.Errorf("unknown command %q; run 'kinfold help'", args[0])
	}
}

func noArgs(f *flag.FlagSet) error {
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", f.Args())
	}
	return nil
}

func loadWritableState(dir string) (*core.State, *os.File, error) {
	lock, err := core.LockState(dir)
	if err != nil {
		return nil, nil, err
	}
	state, err := core.LoadState(dir)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	return state, lock, nil
}

const maxEnrollmentFileSize = 64 << 10

func readEnrollmentFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxEnrollmentFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEnrollmentFileSize {
		return nil, fmt.Errorf("enrollment file %s exceeds %d bytes", path, maxEnrollmentFileSize)
	}
	return data, nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write %s (an incomplete file may remain): %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync %s (the file may remain): %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s (the file may remain): %w", path, err)
	}
	if err := core.SyncParentDir(path); err != nil {
		return fmt.Errorf("sync parent of %s (file exists but durability is uncertain): %w", path, err)
	}
	return nil
}
