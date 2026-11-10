package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/metrics"
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
  run          Run the client tunnel (Linux and macOS)
  token        Issue a single-use online enrollment token (controller)
  token-list   List pending enrollment tokens
  token-revoke Revoke a pending enrollment token
  join         Enroll this device online with a token
  seen-reset   Reset the configuration rollback watermark of a credential
  replica-add  Register a standby controller and write its credential
  replica-remove Remove a standby controller
  replica-promote Turn a stopped standby into the primary
  renew        Renew this device's certificate if it is due
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
		server := f.String("server", "", "move the controller to this new host:port (devices need the new address in their credential)")
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
		if *server != "" {
			err = s.ChangeServerAddress(*server)
		} else {
			err = s.RenewServerCertificate()
		}
		if err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		if *server != "" {
			fmt.Printf("Controller moved to %s on disk; restart the controller and set \"server\" to %s in every device credential.\n", *server, *server)
			return nil
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
		remote, id, err := agent.FetchConfig(ctx, cred)
		if err != nil {
			return err
		}
		// The controller serves each device only its own view; compare the
		// same view of the on-disk state.
		localRevision, err := local.Config.ForPeer(id).Revision()
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
			s.DropTokens(*id, *ip)
		} else {
			cert, err = s.RotatePeerEnrollment(*id, request)
		}
		if err != nil {
			return err
		}
		// The state is written first, so a certificate never exists outside
		// the member list. The certificate is public: if it cannot be
		// written, it is printed instead of being lost (the key is then
		// recorded in the key history and cannot be approved again).
		if err := checkNewOutput(*out); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return fmt.Errorf("controller state update failed or its durability is uncertain: %w", err)
		}
		if err := writeNew(*out, cert); err != nil {
			fmt.Printf("%s", cert)
			return fmt.Errorf("controller state updated, but %w; the certificate is printed above", err)
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
		s.DropTokens(*id, *ip) // a leftover token must not re-enroll this device later
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return err
		}
		if err := checkNewOutput(*out); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return fmt.Errorf("controller state update failed or its durability is uncertain: %w", err)
		}
		if err := writeNew(*out, append(data, '\n')); err != nil {
			return fmt.Errorf("%s is authorized, but %w; run remove-peer -id %s and add it again", *id, err, *id)
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
		s.ForgetPeer(*id)
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
		metricsAddr := f.String("metrics", "", "serve Prometheus metrics on this loopback host:port (disabled when empty)")
		maxConns := f.Int("max-conns", relay.DefaultListenerLimits.Total, "maximum concurrent TCP connections")
		maxPerIP := f.Int("max-conns-per-ip", relay.DefaultListenerLimits.PerSource, "maximum concurrent TCP connections per source IP (0 disables)")
		ratePerIP := f.Float64("conn-rate-per-ip", relay.DefaultListenerLimits.RatePerSource, "new TCP connections per second per source IP (0 disables)")
		relayRate := f.String("relay-rate", "0", "per-device relay bandwidth limit in bytes per second, with optional k/M/G suffix (0 disables)")
		relayBurst := f.String("relay-burst", "", "per-device relay burst in bytes, with optional k/M/G suffix (default: one second at -relay-rate; at least 16 KiB)")
		standbyCred := f.String("standby", "", "run as read-only standby replicating from the primary named in this replica credential")
		standbyMaxAge := f.Duration("standby-max-age", defaultStandbyMaxAge, "standby: stop serving devices when the state could not be replicated for this long")
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
		rate, err := parseBytes(*relayRate)
		if err != nil {
			return fmt.Errorf("-relay-rate: %w", err)
		}
		// Below one byte per second the pause computation overflows and
		// would switch the limit off (v0.6 review finding 1).
		if rate > 0 && rate < 1 {
			return fmt.Errorf("-relay-rate must be 0 (off) or at least 1 byte per second")
		}
		if rate == 0 && *relayBurst != "" {
			return fmt.Errorf("-relay-burst needs -relay-rate")
		}
		burst := rate
		if *relayBurst != "" {
			if burst, err = parseBytes(*relayBurst); err != nil {
				return fmt.Errorf("-relay-burst: %w", err)
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var replica *core.ReplicaCredential
		var rep *replicator
		if *standbyCred != "" {
			cred, err := readReplicaCredential(*standbyCred)
			if err != nil {
				return err
			}
			replica = &cred
			if *standbyMaxAge <= 0 {
				return fmt.Errorf("-standby-max-age must be positive")
			}
			// Before the first replication, so an expired credential is
			// named even when that fails.
			for _, warning := range cred.CertificateWarnings(time.Now(), certificateWarningWindow) {
				slog.Warn(warning + "; renew with replica-remove and replica-add on the primary")
			}
			if rep, err = prepareStandby(ctx, cred, *dir, *standbyMaxAge); err != nil {
				return err
			}
			defer rep.Close()
		}
		loadServed := core.LoadState
		if replica != nil {
			loadServed = core.LoadStandbyState
		}
		s, err := loadServed(*dir)
		if err != nil {
			return err
		}
		if s.Config.Policy == nil {
			return fmt.Errorf("state has no policy section (pre-policy format); run 'kinfold policy-enable -data %s' and add allow rules before serving", *dir)
		}
		if s.ConfigKey == nil && replica == nil {
			// States from before v0.4 have no configuration signing key.
			if s, err = addConfigKey(*dir); err != nil {
				return err
			}
			slog.Info("generated a configuration signing key for this controller")
		}
		handler, err := relay.NewForState(s)
		if err != nil {
			return err
		}
		tlsCfg, err := relay.TLSConfig(s)
		if replica != nil {
			handler.SetStandby()
			rep.setStale = handler.SetStale
			handler.Metrics().GaugeFunc("kinfold_standby_last_replication_timestamp_seconds", "Unix time of the last successful replication from the primary.", nil, func() float64 {
				return float64(rep.lastReplication().Unix())
			})
			tlsCfg, err = relay.TLSConfigWithServer(s, replica.ServerCert, replica.ServerKey)
		}
		if err != nil {
			return err
		}
		if rate > 0 {
			limit := handler.SetRelayLimit(relay.RelayLimit{Rate: rate, Burst: burst})
			slog.Info("relay bandwidth limited per device", "bytes_per_second", limit.Rate, "burst", limit.Burst)
		}
		rejected := handler.Metrics().Counter("kinfold_listener_rejected_total", "Connections closed by per-source limits.", nil)
		limits := relay.ListenerLimits{Total: *maxConns, PerSource: *maxPerIP, RatePerSource: *ratePerIP, BurstPerSource: max(*maxPerIP, 1), OnReject: rejected.Inc}
		handler.Metrics().GaugeFunc("kinfold_build_info", "Build information.", metrics.Labels{"version": Version}, func() float64 { return 1 })
		if *metricsAddr != "" {
			addr, err := metrics.Serve(*metricsAddr, handler.Metrics(), ctx.Done())
			if err != nil {
				return err
			}
			slog.Info("metrics listening", "address", addr.String())
		}
		ln, err := listenController(ctx, *listen, limits)
		if err != nil {
			return err
		}
		tokens := newTokenCache(*dir, s)
		if replica == nil {
			handler.SetRenewer(controllerRenewer(*dir, time.Now))
			handler.SetEnroller(controllerEnroller(*dir, time.Now, tokens))
		} else {
			go rep.run(ctx)
			slog.Info("running as standby", "primary", replica.Primary, "address", replica.Address)
		}
		server := newControllerServer(handler, tlsCfg, defaultServerTimeouts)
		var warned time.Time
		warnCertificates := func(s *core.State) {
			startup := warned.IsZero()
			if !warningsDue(&warned, time.Now()) {
				return
			}
			for _, warning := range s.CertificateWarnings(time.Now(), certificateWarningWindow) {
				slog.Warn(warning)
			}
			if replica != nil && !startup { // already logged above at startup
				for _, warning := range replica.CertificateWarnings(time.Now(), certificateWarningWindow) {
					slog.Warn(warning + "; renew with replica-remove and replica-add on the primary")
				}
			}
		}
		warnCertificates(s)
		slog.Info("controller listening", "address", ln.Addr().String(), "build", readBuildInfo().short(), "peers", len(s.Config.Peers))
		return serveController(ctx, server, ln, handler, func(ctx context.Context) {
			handler.Watch(ctx.Done(), s, func() (*core.State, error) {
				next, err := loadServed(*dir)
				if err == nil {
					tokens.update(next)
					warnCertificates(next)
				}
				return next, err
			}, time.Second)
		}, 5*time.Second)
	case "status", "run":
		f := flags(args[0])
		path := f.String("credential", "", "private peer credential file")
		// status only reads the configuration; the tunnel options exist for
		// run alone, so status -h does not list them.
		iface, metricsAddr, directListen := new(string), new(string), new(string)
		autoRenew, directDial := new(bool), new(bool)
		var logging logFlags
		if args[0] == "run" {
			iface = f.String("interface", "kf0", "new TUN interface name (Linux only; macOS picks utunN)")
			metricsAddr = f.String("metrics", "", "serve Prometheus metrics on this loopback host:port (disabled when empty)")
			autoRenew = f.Bool("auto-renew", true, "renew the device certificate automatically before it expires")
			directListen = f.String("direct-listen", "", "accept direct peer sessions on this host:port, e.g. :51900 (empty disables)")
			directDial = f.Bool("direct-dial", true, "dial peers that accept direct sessions before falling back to the relay")
			logging = addLogFlags(f)
		}
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
		if args[0] == "run" && *autoRenew {
			var err error
			if cred, err = resumeRenewal(ctx, *path, cred); err != nil {
				return err
			}
		}
		if args[0] == "run" {
			var err error
			if cred, err = pinConfigKey(ctx, *path, cred); err != nil {
				return err
			}
		}
		var cfg core.Config
		var id string
		var err error
		if args[0] == "run" {
			// The configuration that starts the tunnel must respect the
			// persisted rollback watermark too (v0.4 review finding 1).
			cfg, id, err = fetchWithWatermark(ctx, *path, cred)
		} else {
			cfg, id, err = agent.FetchConfig(ctx, cred)
		}
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
		if *metricsAddr != "" {
			agent.Metrics.GaugeFunc("kinfold_build_info", "Build information.", metrics.Labels{"version": Version}, func() float64 { return 1 })
			addr, err := metrics.Serve(*metricsAddr, agent.Metrics, ctx.Done())
			if err != nil {
				return err
			}
			slog.Info("metrics listening", "address", addr.String())
		}
		direct := directOptions{dial: *directDial, listen: *directListen}
		if *directListen != "" {
			_, port, err := net.SplitHostPort(*directListen)
			if direct.port, err = strconv.Atoi(port); err != nil || direct.port < 1 || direct.port > 65535 {
				return fmt.Errorf("-direct-listen needs an explicit port, e.g. :51900")
			}
			direct.addrs = localAddresses()
		}
		return runSupervised(ctx, *path, cred, cfg, id, *iface, *autoRenew, direct)
	case "renew":
		f := flags("renew")
		path := f.String("credential", "", "private peer credential file to renew in place")
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
		var cred core.Credential
		if err := core.ReadJSON(*path, &cred); err != nil {
			return err
		}
		cert, err := credentialCertificate(cred)
		if err != nil {
			return err
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		client := agent.NewConfigClient(cred)
		defer client.Close()
		renewed, ok, err := renewCredential(ctx, *path, cred, client, time.Now())
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("Certificate valid until %s; renewal is not due yet.\n", cert.NotAfter.UTC().Format(time.DateOnly))
			return nil
		}
		next, err := credentialCertificate(renewed)
		if err != nil {
			return err
		}
		fmt.Printf("Renewed certificate in %s, valid until %s. Restart a running client to use it.\n", *path, next.NotAfter.UTC().Format(time.DateOnly))
		return nil
	case "token":
		f := flags("token")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "device ID the token enrolls")
		ip := f.String("ip", "", "IPv4 address the device receives")
		ttl := f.Duration("ttl", core.DefaultTokenTTL, "token lifetime (at most 168h)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *ip == "" {
			return fmt.Errorf("-id and -ip are required")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		secret, err := s.IssueToken(*id, *ip, *ttl, time.Now())
		if err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		caFP, err := caFingerprint(s)
		if err != nil {
			return err
		}
		fmt.Printf("Enrollment token for %s (%s), valid until %s, single use:\n\n  %s\n\n", *id, *ip, s.EnrollmentTokens[len(s.EnrollmentTokens)-1].NotAfter.Format(time.RFC3339), secret)
		fmt.Printf("Give the device the token and this command over a confidential channel; the device reads the token from standard input so it does not appear in process lists:\n\n  kinfold join -server %s -ca-sha256 %s -id %s -token-file - -out %s.json\n\n(Use the name or path of the binary on the device instead of kinfold.)\n\n", s.Server, caFP, *id, *id)
		fmt.Println("The token is shown only once; revoke it with token-revoke if it leaks.")
		return nil
	case "token-list":
		f := flags("token-list")
		dir := f.String("data", "controller-data", "controller data directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		s, err := core.LoadState(*dir)
		if err != nil {
			return err
		}
		s.PruneTokens(time.Now())
		if len(s.EnrollmentTokens) == 0 {
			fmt.Println("No pending enrollment tokens.")
		}
		for _, t := range s.EnrollmentTokens {
			fmt.Printf("  %s  %s  valid until %s\n", t.ID, t.IP, t.NotAfter.Format(time.RFC3339))
		}
		return nil
	case "token-revoke":
		f := flags("token-revoke")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "device ID whose pending token to revoke")
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
		if !s.RevokeToken(*id) {
			return fmt.Errorf("no pending token for %q", *id)
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Printf("Revoked the pending enrollment token for %s.\n", *id)
		return nil
	case "join":
		f := flags("join")
		server := f.String("server", "", "controller host:port")
		fp := f.String("ca-sha256", "", "SHA-256 fingerprint of the controller CA (from the administrator)")
		id := f.String("id", "", "device ID the token was issued for")
		tokenFile := f.String("token-file", "", "file containing the single-use enrollment token, or - for standard input")
		out := f.String("out", "", "new private credential file")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *server == "" || *fp == "" || *id == "" || *tokenFile == "" || *out == "" {
			return fmt.Errorf("-server, -ca-sha256, -id, -token-file and -out are required")
		}
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s already exists", *out)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		cred, err := joinWithToken(ctx, *server, *fp, *id, *tokenFile, *out)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return err
		}
		if err := writeNew(*out, append(data, '\n')); err != nil {
			return fmt.Errorf("%w (the pending enrollment in %s allows a retry)", err, joinPendingPath(*out))
		}
		os.Remove(joinPendingPath(*out))
		fmt.Printf("Enrolled %s. Private credential written to %s.\n", *id, *out)
		return nil
	case "seen-reset":
		f := flags("seen-reset")
		path := f.String("credential", "", "credential whose configuration watermark to reset")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *path == "" {
			return fmt.Errorf("-credential is required")
		}
		if err := os.Remove(seenPath(*path)); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("Configuration watermark removed. Only do this after the controller's clock was set back; the next run accepts the controller's current configuration as the new baseline.")
		return nil
	case "replica-add":
		f := flags("replica-add")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "replica ID")
		address := f.String("address", "", "host:port devices use to reach the standby")
		out := f.String("out", "", "new replica credential file (contains private keys)")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *id == "" || *address == "" || *out == "" {
			return fmt.Errorf("-id, -address and -out are required")
		}
		s, lock, err := loadWritableState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		cred, err := s.AddReplica(*id, *address)
		if err != nil {
			return err
		}
		data, err := json.MarshalIndent(cred, "", "  ")
		if err != nil {
			return err
		}
		if err := checkNewOutput(*out); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return fmt.Errorf("controller state update failed: %w", err)
		}
		if err := writeNew(*out, append(data, '\n')); err != nil {
			return fmt.Errorf("standby %s is registered, but %w; run replica-remove -id %s and add it again", *id, err, *id)
		}
		fmt.Printf("Added standby %s at %s. Transfer %s securely to the standby host; it receives a full copy of the controller state, including the CA key.\n", *id, *address, *out)
		return nil
	case "replica-remove":
		f := flags("replica-remove")
		dir := f.String("data", "controller-data", "controller data directory")
		id := f.String("id", "", "replica ID")
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
		if !s.RemoveReplica(*id) {
			return fmt.Errorf("unknown replica %q", *id)
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Printf("Removed standby %s; it can no longer replicate. Its copy of the state still contains the CA key: destroy it.\n", *id)
		return nil
	case "replica-promote":
		f := flags("replica-promote")
		dir := f.String("data", "controller-data", "standby data directory")
		credPath := f.String("standby", "", "replica credential of this standby")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if err := noArgs(f); err != nil {
			return err
		}
		if *credPath == "" {
			return fmt.Errorf("-standby is required")
		}
		cred, err := readReplicaCredential(*credPath)
		if err != nil {
			return err
		}
		lock, err := core.LockState(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		// The replicated state carries the old primary's server certificate,
		// which may have expired while the primary was down.
		s, err := core.LoadStateForOfflineMaintenance(*dir)
		if err != nil {
			return err
		}
		old := s.Server
		if err := s.Promote(cred); err != nil {
			return err
		}
		if err := core.WriteJSON(filepath.Join(*dir, "state.json"), s); err != nil {
			return err
		}
		fmt.Printf("This controller is now the primary at %s (was %s). Start it without -standby. Make sure %s cannot come back as primary; re-create other standbys with replica-add here.\n", s.Server, old, old)
		return nil
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

// A controller runs for months: certificate expiry warnings are repeated
// daily instead of being logged at startup only (D-041).
const (
	certificateWarningWindow   = 30 * 24 * time.Hour
	certificateWarningInterval = 24 * time.Hour
)

// warningsDue reports whether the interval since *last has passed, and
// then records now as the time of the warnings.
func warningsDue(last *time.Time, now time.Time) bool {
	if now.Sub(*last) < certificateWarningInterval {
		return false
	}
	*last = now
	return true
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

// parseBytes reads a byte count with an optional decimal k, M or G suffix.
func parseBytes(v string) (float64, error) {
	scale := 1.0
	switch {
	case strings.HasSuffix(v, "k"), strings.HasSuffix(v, "K"):
		scale, v = 1e3, v[:len(v)-1]
	case strings.HasSuffix(v, "M"):
		scale, v = 1e6, v[:len(v)-1]
	case strings.HasSuffix(v, "G"):
		scale, v = 1e9, v[:len(v)-1]
	}
	n, err := strconv.ParseFloat(v, 64)
	n *= scale
	if err != nil || n < 0 || math.IsInf(n, 0) || math.IsNaN(n) || n > 1e15 {
		return 0, fmt.Errorf("invalid byte count %q", v)
	}
	return n, nil
}

// checkNewOutput catches the common reasons writeNew would fail (existing
// file, missing directory) before the controller state is changed.
func checkNewOutput(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output directory %s is not a directory", filepath.Dir(path))
	}
	return nil
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
