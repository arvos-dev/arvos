# Package as a container image

* Status: accepted
* Deciders: Cristian, Emil
* Date: 2021-10-26

## Context and Problem Statement

As identified via user interviews, ARVOS needs to be packaged as easily as possible to reduce the barrier of adoption.

How exactly should we package ARVOS?

## Decision Drivers

* ARVOS needs to be easy to run on a variety of platforms
* Packaging should not require to much effort

## Considered Options

* Package as an APT (deb) package
* Package as a container image

## Decision Outcome

Chosen option: "package as a container image", because the requirements allow us to assume that the Docker runtime is already present on the system where ARVOS is to be launched. This means that the user can already run ARVOS, without needing to install anything else.

For CI/CD environments, ARVOS will be launched as a privileged container, which talks to the Docker Daemon, e.g.:

```
docker run -v /var/run/docker.sock:/var/run/docker.sock --privileged arvos -- --image myapp-test mvn test
```

For Kubernetes environments, ARVOS will run as a privileged DaemonSet, which talks to each host's Docker Daemon, e.g.:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: arvos
  namespace: arvos-system
spec:
  selector:
    matchLabels:
      name: arvos
  template:
    metadata:
      labels:
        name: arvos
    spec:
      containers:
      - name: arvosfluentd-elasticsearch
        image: arvos:v1.1.1
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        securityContext:
          privileged: true
          runAsUser: 0
        volumeMounts:
        - name: dockerdock
          mountPath: /var/run/docker.sock
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      volumes:
      - name: dockersock
        hostPath:
          path: /var/run/docker.sock
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
```

## Links

* [Privileged containers](https://docs.docker.com/engine/reference/commandline/run/#full-container-capabilities---privileged)
* [DaemonSet](https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/)
