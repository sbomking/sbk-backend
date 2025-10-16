# Getting started


## Tracing
docker run --rm --name jaeger -p 16686:16686 -p 4317:4317 -p 4318:4318 -p 5778:5778 -p 9411:9411 cr.jaegertracing.io/jaegertracing/jaeger:2.11.0

apiVersion: v1
kind: Pod
metadata:
  labels:
    app: jaeger-pod
  name: jaeger-pod
spec:
  containers:
  - image: cr.jaegertracing.io/jaegertracing/jaeger:2.11.0
    name: jaeger
    ports:
    - containerPort: 4317
      hostPort: 4317
    - containerPort: 4318
      hostPort: 4318
    - containerPort: 5778
      hostPort: 5778
    - containerPort: 9411
      hostPort: 9411
    - containerPort: 16686
      hostPort: 16686
    securityContext:
      runAsNonRoot: true
    volumeMounts:
    - mountPath: /tmp
      name: jaegertracing-pvc
  volumes:
  - name: jaegertracing-pvc
    persistentVolumeClaim:
      claimName: jaegertracing


## Scanner

### Trivy
