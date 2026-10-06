{{- define "agentplane.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 54 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 54 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "agentplane.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "agentplane.selector" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* "true" when the journal is a redb file; a store from a Secret is Postgres. */}}
{{- define "agentplane.redb" -}}
{{- if .Values.storeSecret.existingSecret -}}false
{{- else if or (hasPrefix "postgres://" .Values.store) (hasPrefix "postgresql://" .Values.store) -}}false
{{- else -}}true
{{- end -}}
{{- end -}}

{{/* The Secrets `serve` reads at start, as the cluster holds them now; empty under `helm template`. */}}
{{- define "agentplane.secrets" -}}
{{- range list .Values.tokens.existingSecret .Values.storeSecret.existingSecret -}}
{{- if . -}}{{- (lookup "v1" "Secret" $.Release.Namespace .).data | toJson -}}{{- end -}}
{{- end -}}
{{- end -}}

{{/* The refusals, rendered before anything else is. */}}
{{- define "agentplane.validate" -}}
{{- if not .Values.tokens.existingSecret -}}
{{- fail "tokens.existingSecret is required: the token file is mounted from a Secret you create, never rendered from values" -}}
{{- end -}}
{{- if and .Values.store .Values.storeSecret.existingSecret -}}
{{- fail "store and storeSecret.existingSecret name two stores; set one" -}}
{{- end -}}
{{- if not (or .Values.store .Values.storeSecret.existingSecret) -}}
{{- fail "a store is required: storeSecret.existingSecret naming a Secret that holds a postgres:// connection string, or store: a redb path under /data for one replica" -}}
{{- end -}}
{{- if regexMatch "^postgres(ql)?://[^/@]*:[^/@]*@" .Values.store -}}
{{- fail "store holds a password, which would render into the pod's args: put the connection string in a Secret and set storeSecret.existingSecret" -}}
{{- end -}}
{{- if and (gt (int .Values.replicas) 1) (include "agentplane.redb" . | eq "true") -}}
{{- fail "replicas > 1 needs a Postgres store (store: postgres://…): a redb file admits one writer process" -}}
{{- end -}}
{{- if not .Values.manifest -}}
{{- fail "manifest is required: --set-file manifest=plane/agent.yaml" -}}
{{- end -}}
{{- if not .Values.policy -}}
{{- fail "policy is required: --set-file policy=plane/policy.cedar" -}}
{{- end -}}
{{- end -}}
