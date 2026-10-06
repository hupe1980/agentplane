# agentplane Helm chart

One plane: the A2A, MCP and operator listeners of `agentplane serve`, from the
`:full` image. Not published to a chart repository; install it from this
directory.

```sh
agentplane init --serve plane     # or the container form on the getting-started page
kubectl create secret generic agentplane-tokens --from-file=tokens.yaml=plane/tokens.yaml
# Your Postgres, with its password: the connection string is a Secret, read
# into the pod's environment, never rendered into its args.
kubectl create secret generic agentplane-store \
  --from-literal=store="postgres://agentplane:$(cat pg-password)@postgres:5432/agentplane?sslmode=require"
helm install plane deploy/helm/agentplane \
  --set-file manifest=plane/agent.yaml \
  --set-file policy=plane/policy.cedar \
  --set tokens.existingSecret=agentplane-tokens \
  --set storeSecret.existingSecret=agentplane-store
```

`store` (a plain value) is for a redb path, or a Postgres connection string
with no password — one whose server authenticates by other means, such as
client certificates. A `store` holding a password is refused at render time.
A passwordless string against a server that trusts the network admits every
pod that can reach it, so never point one at `trust` authentication.

## What it renders

- **A Deployment** running as UID 65532 with a read-only root filesystem, no
  privilege escalation and every capability dropped. The manifest and policy
  come from a ConfigMap and the token file from your Secret, both mounted
  read-only; a token is never a value and never an environment variable. The
  store's connection string comes from its Secret as `AGENTPLANE_STORE`.
- **Two Services.** One fronts A2A (`8080`) and MCP (`8081`). The operator
  listener (`9090`) — halts, cancellations, reconciliation — is on its own
  Service, always `ClusterIP`, and never on the first. With more than one
  replica the first sets `sessionAffinity: ClientIP`: a `2025-11-25` MCP
  session lives in the memory of the pod that opened it, and any other pod
  answers it `404`. Behind an ingress that hides client addresses, route on the
  `Mcp-Session-Id` header instead.
- **HTTP probes on the Agent Card**, which is served unauthenticated by design;
  the image has no shell for an exec probe.

## The rules it enforces at render time

- **More than one replica needs a Postgres store.** A redb file admits one
  writer process, so `replicas > 1` with any other `store` fails to render. A
  redb plane is rolled with `Recreate`, so the old pod releases the file before
  the new one opens it.
- **The grace period exceeds the drain.** `serve` drains for `drainSeconds` on
  `SIGTERM`; the pod gets ten seconds more, or the kubelet kills runs mid-effect
  and their effects wait for a person.
- **`tokens.existingSecret`, `manifest`, `policy` and one store are
  required** — `storeSecret.existingSecret` or `store`, not both.
- **No password in the pod's args.** A `store` of the form
  `postgres://user:password@…` fails to render.

## What it does not do

It reconciles nothing. A plane holds its declarations from start, an open run
stays pinned to the revision it began under, and a resume under another
revision is quarantined — so the only safe response to a changed manifest or
policy is a new pod, which is what an upgrade is: the ConfigMap's checksum is a
pod annotation, and changing either rolls the Deployment. A controller watching
manifests would have no other act available, which is why the project ships
none.

`serve` reads the token file and the store once, at start, and never reloads
them. The chart hashes both Secrets as the cluster holds them into a pod
annotation, so a rotation followed by `helm upgrade` rolls the Deployment; a
rotation with no upgrade needs `kubectl rollout restart deployment/<name>`.

`url` defaults to the in-cluster Service; set it, and add the external host to
`mcp.allowedHosts`, when callers reach the plane through an ingress.
