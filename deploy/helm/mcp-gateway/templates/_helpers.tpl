{{- define "mcp-gateway.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "mcp-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "mcp-gateway.labels" -}}
{{ include "mcp-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* gateway.yaml: the values' config, with what the pod's layout fixes
     and the cluster's issuer added to http.issuers. */}}
{{- define "mcp-gateway.config" -}}
{{- $cfg := deepCopy (default dict .Values.config) -}}
{{- $http := deepCopy (default dict $cfg.http) -}}
{{- $issuers := default list $http.issuers -}}
{{- if .Values.clusterIssuer.enabled -}}
{{- $ci := .Values.clusterIssuer -}}
{{- $issuers = append $issuers (dict
      "issuer" $ci.issuer
      "audience" $ci.audience
      "ca_file" "/etc/mcp-gateway/cluster-ca/ca.crt"
      "jwks_url" (printf "%s/openid/v1/jwks" (trimSuffix "/" $ci.issuer))
      "token_file" "/var/run/secrets/mcp-gateway/token/token"
      "scopes" list
      "subject_prefix" $ci.subjectPrefix) -}}
{{- end -}}
{{- $_ := set $http "listen" ":8443" -}}
{{- $_ := set $http "cert_file" "/etc/mcp-gateway/tls/tls.crt" -}}
{{- $_ := set $http "key_file" "/etc/mcp-gateway/tls/tls.key" -}}
{{- if $issuers }}{{ $_ := set $http "issuers" $issuers }}{{ end -}}
{{- if .Values.kubernetesLauncher.enabled -}}
{{- $kl := .Values.kubernetesLauncher -}}
{{- $sup := deepCopy (default dict $cfg.supervisor) -}}
{{- $_ := set $sup "mode" "kubernetes" -}}
{{- $_ := set $sup "kubernetes" (dict
      "namespace" $kl.namespace
      "bridge_image" (include "mcp-gateway.image" .)
      "image_pull_policy" $kl.imagePullPolicy
      "start_timeout" $kl.startTimeout
      "selinux" $kl.selinux
      "gateway_namespace" .Release.Namespace
      "gateway_labels" (include "mcp-gateway.selectorLabels" . | fromYaml)) -}}
{{- $_ := set $cfg "supervisor" $sup -}}
{{- end -}}
{{- if .Values.replication.enabled -}}
{{- $rep := dict "store" "kubernetes" "namespace" .Release.Namespace -}}
{{- if .Values.replication.peerSecret -}}
{{- $_ := set $rep "listen" ":8444" -}}
{{- $_ := set $rep "peer_cert_file" "/etc/mcp-gateway/peer/tls.crt" -}}
{{- $_ := set $rep "peer_key_file" "/etc/mcp-gateway/peer/tls.key" -}}
{{- $_ := set $rep "peer_ca_file" "/etc/mcp-gateway/peer/ca.crt" -}}
{{- end -}}
{{- $_ := set $cfg "replication" $rep -}}
{{- end -}}
{{- with .Values.serverDiscovery.namespaces -}}
{{- $sd := dict "namespaces" . -}}
{{- with $.Values.serverDiscovery.selector }}{{ $_ := set $sd "selector" . }}{{ end -}}
{{- $_ := set $cfg "server_discovery" $sd -}}
{{- end -}}
{{- $policy := deepCopy (default dict $cfg.policy) -}}
{{- $_ := set $policy "opa_socket" "/run/mcp-gateway/opa.sock" -}}
{{- $_ := set $cfg "version" 1 -}}
{{- $_ := set $cfg "deployment" "container" -}}
{{- $_ := set $cfg "servers_dir" "/etc/mcp-gateway/servers.d" -}}
{{- $_ := set $cfg "state_dir" "/var/lib/mcp-gateway" -}}
{{- $_ := set $cfg "policy" $policy -}}
{{- $_ := set $cfg "metrics" (dict "listen" ":9464") -}}
{{- $_ := set $cfg "http" $http -}}
{{- toYaml $cfg -}}
{{- end -}}

{{- define "mcp-gateway.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "mcp-gateway.restricted" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
