# LunaGuard Security Service

The comprehensive security and authentication service for the LunaGuard platform, built in Go to provide high-performance authentication, authorization, network control, and security policy enforcement.

## 🎯 Service Overview

The **LunaGuard Security** service combines authentication, authorization, and advanced security features into a single high-performance Go service:

## 🔐 Core Responsibilities

### 1. **Authentication & Authorization**

- **Dual Authentication System**
  - 🔐 Local Authentication: Email/password with JWT tokens
  - 🌐 OAuth 2.0: Google OAuth (extensible to GitHub, Apple, etc.)
- **🔒 Security First**
  - JWT access tokens (15-min expiry) + refresh tokens (7-day expiry)
  - HttpOnly cookies for OAuth flow security
  - bcrypt password hashing
  - Token rotation and revocation
  - Device tracking and session management

### 2. **Network Control & Policies**

- **Access Control Lists (ACLs)**
  - IP-based access restrictions
  - Geo-location filtering
  - Time-based access policies
  - Device fingerprinting and allowlisting
- **Rate Limiting & DDoS Protection**
  - Adaptive rate limiting per user/IP
  - Distributed rate limiting across instances
  - Automatic threat detection and blocking
  - Traffic shaping and prioritization

### 3. **Security Policy Enforcement**

- **Policy Engine**
  - RBAC (Role-Based Access Control)
  - ABAC (Attribute-Based Access Control)
  - Dynamic policy evaluation
  - Policy inheritance and delegation
- **Compliance & Auditing**
  - Security event logging
  - Real-time security monitoring
  - Automated incident response

### 4. **Advanced Security Features**

- **Threat Detection**
  - Anomaly detection for login patterns
  - Brute force attack prevention
  - Session hijacking detection
  - Suspicious activity alerting
- **Zero Trust Architecture**
  - Continuous authentication verification
  - Micro-segmentation support
  - Context-aware access decisions
  - Trust score calculation

## 🏗️ Architecture Integration

```mermaid
graph TB
    subgraph "Client Layer"
        UI[Web UI]
        API[API Clients]
        MOBILE[Mobile Apps]
    end

    subgraph "Security Layer (Go)"
        SEC[LunaGuard Security<br/>Auth + Policies + Network Control]
    end

    subgraph "Core Services (Python)"
        CONTROLLER[Central Controller<br/>Orchestration]
    end

    subgraph "Backend Services"
        STORAGE[Storage Service]
        MONITORING[Monitoring Service]
    end

    UI --> SEC
    API --> SEC
    MOBILE --> SEC

    SEC --> CONTROLLER
    CONTROLLER --> STORAGE
    CONTROLLER --> MONITORING

    SEC -.-> STORAGE
    SEC -.-> MONITORING
```

The security service acts as the primary gateway, validating all requests before forwarding them to the central controller.

## � Features

### Authentication System

- **JWT Token Management**

  - Access tokens (15-minute expiry) for API requests
  - Refresh tokens (7-day expiry) for token renewal
  - Token rotation and revocation
  - Secure token storage and validation

- **OAuth 2.0 Integration**

  - Google OAuth with PKCE
  - Extensible to GitHub, Apple, Microsoft
  - HttpOnly cookies for web security
  - State parameter validation

- **Multi-Factor Authentication (Planned)**
  - TOTP (Time-based One-Time Password)
  - SMS verification
  - Hardware security keys (WebAuthn)
  - Backup codes

### Network Security

- **IP Access Control**

  - Allowlist/blocklist management
  - CIDR range support
  - Dynamic IP reputation scoring
  - Geo-blocking capabilities

- **DDoS Protection**

  - Rate limiting per endpoint
  - Sliding window algorithms
  - Distributed coordination via Redis
  - Automatic mitigation responses

- **Traffic Analysis**
  - Real-time traffic monitoring
  - Anomaly detection algorithms
  - Pattern recognition for attacks
  - Automated response triggers

### Policy Management

- **Role-Based Access Control (RBAC)**

  - Hierarchical role definitions
  - Permission inheritance
  - Dynamic role assignment
  - Role-based resource access

- **Attribute-Based Access Control (ABAC)**

  - Context-aware access decisions
  - Policy expression language
  - Real-time attribute evaluation
  - Fine-grained permissions

- **Security Policies**
  - Password complexity requirements
  - Session timeout policies
  - Account lockout rules
  - Security question enforcement

## 📡 API Endpoints

### Base URL

```
http://localhost:8001
```

### Authentication Endpoints

#### 🆕 Register New User

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "name": "John Doe"
}
```

#### 🔑 Login User

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

#### 🔄 Refresh Token

```http
POST /auth/refresh
Content-Type: application/json
Authorization: Bearer {refresh_token}
```

#### 🌐 OAuth Routes

```http
GET /auth/google                    # Start Google OAuth
GET /auth/google/callback           # OAuth callback
POST /auth/logout                   # Logout (clears cookies)
GET /auth/user                      # Current user info
```

## 🏗️ Architecture Integration

```mermaid
graph TB
    AUTH[LunaGuard-server<br/>Authentication] --> SEC1[LunaGuard-leak-detector]
    AUTH --> SEC2[LunaGuard-compliance]
    AUTH --> SEC3[LunaGuard-anomaly]
    AUTH --> SEC4[LunaGuard-integrations]
    AUTH --> SEC5[LunaGuard-iac-scanner]

    SEC1 --> ALERT[Alert System]
    SEC2 --> DASH[Compliance Dashboard]
    SEC3 --> ML[(ML Models)]
    SEC4 --> LEGACY[Legacy Systems]
    SEC5 --> GIT[Git Repositories]

    subgraph "Python Microservices"
        SEC1
        SEC2
        SEC3
        SEC4
        SEC5
    end
```

## 🚀 Implementation Roadmap

### Phase 1: Core Security

1. **Leak Detection Worker** - High priority for immediate security
2. **Compliance Checker** - Essential for enterprise adoption

### Phase 2: Advanced Analytics

3. **Anomaly Detection Engine** - ML-powered threat detection
4. **IaC Compliance Bot** - DevOps integration

### Phase 3: Legacy Support

5. **Integration Scripts** - Enterprise legacy system support

## 🔧 Technology Requirements

- **Runtime**: Python 3.9+
- **Frameworks**: FastAPI, Celery for async tasks
- **ML Libraries**: scikit-learn, pandas, numpy
- **Database**: PostgreSQL (shared with core services)
- **Message Queue**: Redis/RabbitMQ for task queuing
- **Monitoring**: Prometheus, Grafana
- **Containerization**: Docker, Kubernetesal features, build in Python:
- **Leak Detection Worker** → periodically scans public repos, artifact registries, and CI/CD logs for leaked secrets (using regex + entropy checks).
- **Security Compliance Checker** → policy evaluation (e.g., secret age, key length) and scoring.
- **Anomaly Detection Engine** → ML-based detection of unusual secret usage patterns.
- **Integration Scripts** → for legacy systems that don’t have native Go clients.
- **IaC Compliance Bot** → scans Terraform/Helm repos for hard-coded secrets before merge.
-
