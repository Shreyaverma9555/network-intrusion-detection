# Kubernetes deployment

1. Build and push both images, then replace 'YOUR_ORG' in the deployments.
2. Copy 'secret.example.yaml' to 'secret.yaml' and replace every secret.
3. Replace the example domains in 'configmap.yaml' and 'ingress.yaml'.
4. Apply with 'kubectl apply -k deploy/kubernetes'.

The API deliberately runs with one replica because its WebSocket event bus is
in-process. For horizontal API scaling, replace the event bus with Redis Pub/Sub
before increasing replicas. The frontend is stateless and can scale freely.

The Scapy sensor normally runs outside Kubernetes on the monitored endpoint or
gateway and posts to the API ingress.
