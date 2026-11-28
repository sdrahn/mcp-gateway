package kube

import "net/url"

// ServicesPath is the collection of a namespace's Services.
func ServicesPath(ns string) string {
	return "/api/v1/namespaces/" + url.PathEscape(ns) + "/services"
}

// Service is a v1 Service, as far as the discovery of servers reads it
// (docs/architecture.md, section 5.12.8).
type Service struct {
	APIVersion string      `json:"apiVersion,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Metadata   ObjectMeta  `json:"metadata"`
	Spec       ServiceSpec `json:"spec"`
}

// ServiceSpec is a Service's type and ports.
type ServiceSpec struct {
	// Type is ClusterIP (also when empty), NodePort, LoadBalancer or
	// ExternalName.
	Type  string        `json:"type,omitempty"`
	Ports []ServicePort `json:"ports,omitempty"`
}

// ServicePort is a port of a Service.
type ServicePort struct {
	Name     string `json:"name,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// ServiceList is a v1 ServiceList.
type ServiceList struct {
	Metadata ListMeta  `json:"metadata"`
	Items    []Service `json:"items"`
}
