# Kubernetes XDP Deployment Notes

`proxy.security.xdp` needs more than container privileged mode. The process must
see the host network namespace and a real bpffs mount at `/sys/fs/bpf`.

Minimal pod requirements:

```yaml
spec:
  hostNetwork: true
  containers:
    - name: sigproxy
      image: 1228022817/sigproxy-rs:latest
      securityContext:
        privileged: true
        capabilities:
          add:
            - NET_ADMIN
            - BPF
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
        - name: config
          mountPath: /etc/sigproxy/config.toml
          subPath: config.toml
          readOnly: true
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
    - name: config
      configMap:
        name: sigproxy-config
```

An apply-ready DaemonSet example lives in `k8s/sigproxy-xdp.yaml`. Adjust the
image tag, upstream server list, namespace, and trusted CIDRs before applying it.

Before scheduling the pod, make sure every target node has bpffs mounted:

```bash
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
```

If the pod logs mention that `/sys/fs/bpf` is missing or is not a bpffs mount,
privileged mode is not enough; fix the host mount and hostPath first.

When `interfaces = []`, sigproxy auto-selects interfaces from the default route
visible inside the pod. With `hostNetwork: true`, that is the node route. Without
`hostNetwork: true`, it is usually only the pod veth and is not suitable for
node ingress XDP filtering.

For strict deployments, set:

```toml
[proxy.security.xdp]
enabled = true
fail_open = false
```

With `fail_open = false`, sigproxy refuses to start if XDP cannot attach.
