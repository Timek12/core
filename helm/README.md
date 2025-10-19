# Helm Charts

This directory contains Helm charts for deploying the application infrastructure and core services.

## Charts

### 1. Infrastructure Chart (`infrastructure/`)

Deploys the infrastructure components:

- **PostgreSQL (Security)**: Database for the security service
- **PostgreSQL (Storage)**: Database for the storage service
- **Redis**: In-memory data store for caching and session management
- **Redis Commander**: Web-based Redis management UI
- **PgAdmin**: Web-based PostgreSQL management UI

All infrastructure components are deployed in the `infrastructure` namespace.

### 2. Core Application Chart (`core-app/`)

Deploys the application microservices:

- **Security Service**: Authentication and authorization
- **Server Service**: Main application server
- **Storage Service**: Data storage and key management
- **UI**: Web-based user interface

Each microservice is deployed in its own namespace:

- `security` namespace for Security service
- `server` namespace for Server service
- `storage` namespace for Storage service
- `ui` namespace for UI service

## Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3.x installed
- kubectl configured to communicate with your cluster
- Sufficient cluster resources (CPU, Memory, Storage)

## Installation

### Step 1: Install Infrastructure

```bash
# Navigate to the helm directory
cd core/helm

# Install infrastructure chart
helm install infrastructure ./infrastructure \
  --namespace infrastructure \
  --create-namespace \
  -f infrastructure/values.yaml
```

### Step 2: Wait for Infrastructure to be Ready

```bash
# Check infrastructure pods
kubectl get pods -n infrastructure

# Wait for all pods to be running
kubectl wait --for=condition=ready pod --all -n infrastructure --timeout=300s
```

### Step 3: Install Core Application

```bash
# Install core application chart
helm install core-app ./core-app \
  -f core-app/values.yaml
```

## Configuration

### Customizing Values

You can customize the deployment by modifying the `values.yaml` file in each chart or by providing your own values file:

```bash
# Using custom values file
helm install infrastructure ./infrastructure \
  --namespace infrastructure \
  --create-namespace \
  -f my-custom-values.yaml
```

### Important Configuration Options

#### Infrastructure Chart

**PostgreSQL Databases:**

```yaml
postgresql-security:
  auth:
    username: security_user
    password: change-this-password # Change in production!
    database: security_db
```

**Redis:**

```yaml
redis:
  auth:
    password: redis_password # Change in production!
```

**PgAdmin:**

```yaml
pgadmin:
  env:
    email: admin@admin.com
    password: admin_password # Change in production!
```

#### Core Application Chart

**Global Settings:**

```yaml
global:
  imageRegistry: ghcr.io
  imageOrganization: lunaguard # Change to your organization
```

**Security Service:**

```yaml
security:
  image:
    tag: latest # Use specific version in production
  secrets:
    JWT_SECRET_KEY: your-jwt-secret-key-change-this # Change in production!
```

**Server Service:**

```yaml
server:
  image:
    tag: latest # Use specific version in production
  env:
    - name: REDIS_HOST
      value: redis.infrastructure.svc.cluster.local
```

**Storage Service:**

```yaml
storage:
  image:
    tag: latest # Use specific version in production
  secrets:
    MASTER_KEY: your-master-encryption-key-change-this # Change in production!
```

**UI Service:**

```yaml
ui:
  service:
    type: LoadBalancer # Use Ingress in production
  env:
    - name: VITE_API_URL
      value: http://server.server.svc.cluster.local:8001
```

## Upgrading

### Upgrade Infrastructure

```bash
helm upgrade infrastructure ./infrastructure \
  --namespace infrastructure \
  -f infrastructure/values.yaml
```

### Upgrade Core Application

```bash
helm upgrade core-app ./core-app \
  -f core-app/values.yaml
```

## Uninstallation

### Uninstall Core Application

```bash
helm uninstall core-app
```

### Uninstall Infrastructure

```bash
helm uninstall infrastructure --namespace infrastructure
```

### Delete Namespaces (Optional)

```bash
kubectl delete namespace security
kubectl delete namespace server
kubectl delete namespace storage
kubectl delete namespace ui
kubectl delete namespace infrastructure
```

## Accessing Services

### Infrastructure Services

**PgAdmin:**

```bash
kubectl port-forward -n infrastructure svc/pgadmin 8080:80
# Access at: http://localhost:8080
```

**Redis Commander:**

```bash
kubectl port-forward -n infrastructure svc/redis-commander 8081:8081
# Access at: http://localhost:8081
```

### Application Services

**UI (if LoadBalancer):**

```bash
kubectl get svc -n ui
# Use the EXTERNAL-IP shown
```

**UI (with port-forward):**

```bash
kubectl port-forward -n ui svc/ui 3000:80
# Access at: http://localhost:3000
```

## Production Recommendations

1. **Use Specific Image Tags**: Never use `latest` in production
2. **Change All Default Passwords**: Update all passwords and secrets
3. **Enable Ingress**: Use Ingress instead of LoadBalancer for UI
4. **Configure Storage Classes**: Specify appropriate storage classes for PVCs
5. **Set Resource Limits**: Adjust CPU and memory limits based on your needs
6. **Enable TLS**: Configure TLS for all services
7. **Use External Secrets**: Consider using tools like Sealed Secrets or External Secrets Operator
8. **Configure Backups**: Set up regular backups for PostgreSQL databases
9. **Monitor Resources**: Use Prometheus and Grafana for monitoring
10. **Set Up Alerts**: Configure alerting for critical issues

## Troubleshooting

### Check Pod Status

```bash
# Check all pods
kubectl get pods --all-namespaces

# Check specific namespace
kubectl get pods -n infrastructure
kubectl get pods -n security
```

### View Pod Logs

```bash
# View logs
kubectl logs -n infrastructure pod-name

# Follow logs
kubectl logs -n infrastructure pod-name -f
```

### Describe Resources

```bash
# Describe pod
kubectl describe pod -n infrastructure pod-name

# Describe service
kubectl describe svc -n infrastructure service-name
```

### Check Helm Releases

```bash
# List all releases
helm list --all-namespaces

# Get release info
helm status infrastructure -n infrastructure
helm status core-app
```

### Common Issues

**Pods in Pending State:**

- Check if PVCs are bound: `kubectl get pvc -n infrastructure`
- Check node resources: `kubectl top nodes`

**ImagePullBackOff:**

- Verify image exists in registry
- Check if image pull secrets are configured

**CrashLoopBackOff:**

- Check pod logs: `kubectl logs -n namespace pod-name`
- Verify environment variables and secrets

## CI/CD Integration

Docker images are automatically built and pushed to GitHub Container Registry (GHCR) via GitHub Actions:

- **Core Services** (security, server, storage): `.github/workflows/core-ci.yml`
- **UI Service**: `.github/workflows/ui-ci.yml`

Images are tagged with:

- Branch name (e.g., `main`, `develop`)
- Git SHA (e.g., `main-abc1234`)
- `latest` (for main branch only)

### Using CI/CD Built Images

Update your `values.yaml` to use specific tags:

```yaml
security:
  image:
    tag: main-abc1234 # Use specific commit SHA

server:
  image:
    tag: v1.0.0 # Or use version tags

storage:
  image:
    tag: develop # Or use branch name
```

## Support

For issues or questions, please check the documentation or create an issue in the repository.
