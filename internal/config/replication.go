package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
)

// Replication configures the shared store of several replicas
// (docs/architecture.md, section 5.12.5, D24): what people reach other
// than the principal it belongs to (grants, approvals, notices, reviews,
// sign-in tokens, the clients seen) kept in the Kubernetes API instead
// of state_dir. Container mode only.
type Replication struct {
	// Store is "" (the default: files in state_dir) or "kubernetes"
	// (Secrets in Namespace).
	Store string `yaml:"store"`
	// Namespace is the gateway's own namespace, where it may get, list,
	// watch, create, update and delete Secrets.
	Namespace string `yaml:"namespace"`
	// APIServer, TokenFile and CAFile reach the Kubernetes API as the
	// gateway's ServiceAccount, with the defaults of
	// supervisor.kubernetes.
	APIServer string `yaml:"api_server"`
	TokenFile string `yaml:"token_file"`
	CAFile    string `yaml:"ca_file"`
	// Replica is this replica's name, Address where the other replicas
	// reach it; by default the pod's name and IP address, from the
	// environment ($POD_NAME, $POD_IP; the downward API).
	Replica string `yaml:"replica"`
	Address string `yaml:"address"`
	// Listen is the peer listener's address (":8444"): the other
	// replicas forward the requests of this replica's principals to it,
	// over TLS with the replicas' certificate (PeerCertFile, PeerKeyFile),
	// which the replicas present as clients too, issued by PeerCAFile, for
	// PeerServerName ("mcp-gateway-peer" by default). Unset: no
	// forwarding (one replica on the store).
	Listen         string `yaml:"listen"`
	PeerCertFile   string `yaml:"peer_cert_file"`
	PeerKeyFile    string `yaml:"peer_key_file"`
	PeerCAFile     string `yaml:"peer_ca_file"`
	PeerServerName string `yaml:"peer_server_name"`
}

// DefaultPeerServerName is the name in the replicas' certificate.
const DefaultPeerServerName = "mcp-gateway-peer"

// Forwarding reports whether the replicas forward to each other.
func (r Replication) Forwarding() bool { return r.Shared() && r.Listen != "" }

// Environment variables the replica's name and address default to.
const (
	ReplicaEnv = "POD_NAME"
	AddressEnv = "POD_IP"
)

// replicaName is a replica's name: a label value.
var replicaName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,61}[a-z0-9])?$`)

// CheckReplica checks the replica's name, after its default.
func CheckReplica(name string) error {
	if name == "" {
		return fmt.Errorf("replication.replica: unset, and $%s is empty (set it from the pod's name with the downward API)", ReplicaEnv)
	}
	if !replicaName.MatchString(name) {
		return fmt.Errorf("replication.replica: %q is not a label value", name)
	}
	return nil
}

// ReplicationKubernetes is the store's value for the Kubernetes API.
const ReplicationKubernetes = "kubernetes"

// WithDefaults returns r with its defaults filled in.
func (r Replication) WithDefaults() Replication {
	if r.APIServer == "" {
		r.APIServer = DefaultKubernetesAPIServer
	}
	if r.PeerServerName == "" {
		r.PeerServerName = DefaultPeerServerName
	}
	if r.TokenFile == "" {
		r.TokenFile = DefaultKubernetesTokenFile
	}
	if r.CAFile == "" {
		r.CAFile = DefaultKubernetesCAFile
	}
	return r
}

// Shared reports whether the state is in the shared store.
func (r Replication) Shared() bool { return r.Store == ReplicationKubernetes }

func (r Replication) validate(container bool) error {
	switch r.Store {
	case "":
		if r != (Replication{}) {
			return errors.New("replication: set store: kubernetes, or nothing")
		}
		return nil
	case ReplicationKubernetes:
	default:
		return fmt.Errorf("replication.store: %q (kubernetes, or unset for files in state_dir)", r.Store)
	}
	if !container {
		return errors.New("replication.store: kubernetes only in container mode (deployment: container); a host keeps its state in state_dir")
	}
	if r.Namespace == "" {
		return errors.New("replication.namespace: required with replication.store: kubernetes (the gateway's own namespace)")
	}
	if !dnsLabel.MatchString(r.Namespace) {
		return fmt.Errorf("replication.namespace: %q is not a namespace name", r.Namespace)
	}
	if r.Replica != "" {
		if err := CheckReplica(r.Replica); err != nil {
			return err
		}
	}
	if r.Listen != "" {
		if _, port, err := net.SplitHostPort(r.Listen); err != nil || port == "" {
			return fmt.Errorf("replication.listen: %q is not host:port (\":8444\")", r.Listen)
		}
		for key, v := range map[string]string{"peer_cert_file": r.PeerCertFile, "peer_key_file": r.PeerKeyFile, "peer_ca_file": r.PeerCAFile} {
			if v == "" {
				return fmt.Errorf("replication.%s: required with replication.listen (the replicas' certificate, key and CA)", key)
			}
		}
	} else if r.PeerCertFile != "" || r.PeerKeyFile != "" || r.PeerCAFile != "" || r.PeerServerName != "" {
		return errors.New("replication.peer_*: only with replication.listen")
	}
	return nil
}
