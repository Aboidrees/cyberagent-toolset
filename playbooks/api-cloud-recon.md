---
id: api-cloud-recon
title: API and Cloud Service Reconnaissance
vars:
  target: "example.com"
  scheme: "https"
  timeout: 10000
  apiTimeout: 15000
steps:
  # API Discovery
  - name: REST API Discovery
    uses: http.get
    with:
      path: "/api"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: API v1 Discovery
    uses: http.get
    with:
      path: "/api/v1"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: API v2 Discovery
    uses: http.get
    with:
      path: "/api/v2"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: GraphQL Endpoint
    uses: http.get
    with:
      path: "/graphql"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: GraphQL Playground
    uses: http.get
    with:
      path: "/graphql/playground"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # API Documentation
  - name: Swagger Documentation
    uses: http.get
    with:
      path: "/swagger"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Swagger UI
    uses: http.get
    with:
      path: "/swagger-ui"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Swagger JSON
    uses: http.get
    with:
      path: "/swagger.json"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: OpenAPI Specification
    uses: http.get
    with:
      path: "/openapi.json"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: API Documentation
    uses: http.get
    with:
      path: "/docs"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Redoc Documentation
    uses: http.get
    with:
      path: "/redoc"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Cloud Service Detection
  - name: AWS S3 Bucket Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      headers:
        Host: "{{vars.target}}.s3.amazonaws.com"
      timeoutMs: "{{vars.timeout}}"

  - name: CloudFront Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: CloudFlare Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Microservices Discovery
  - name: Health Check Endpoint
    uses: http.get
    with:
      path: "/health"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Status Endpoint
    uses: http.get
    with:
      path: "/status"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Metrics Endpoint
    uses: http.get
    with:
      path: "/metrics"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Prometheus Metrics
    uses: http.get
    with:
      path: "/prometheus"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Application Info
    uses: http.get
    with:
      path: "/info"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Container/Orchestration
  - name: Docker Health Check
    uses: http.get
    with:
      path: "/docker/health"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Kubernetes Readiness
    uses: http.get
    with:
      path: "/readiness"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Kubernetes Liveness
    uses: http.get
    with:
      path: "/liveness"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Service Discovery
  - name: Consul Discovery
    uses: http.get
    with:
      path: "/v1/catalog/services"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Eureka Services
    uses: http.get
    with:
      path: "/eureka/apps"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # API Gateway Detection
  - name: Kong Gateway
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: AWS API Gateway
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Zuul Gateway
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Authentication Endpoints
  - name: OAuth Discovery
    uses: http.get
    with:
      path: "/.well-known/openid_configuration"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: OAuth Token Endpoint
    uses: http.get
    with:
      path: "/oauth/token"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: SAML Metadata
    uses: http.get
    with:
      path: "/saml/metadata"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: JWT Well-Known Keys
    uses: http.get
    with:
      path: "/.well-known/jwks.json"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Serverless Detection
  - name: AWS Lambda Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Netlify Functions
    uses: http.get
    with:
      path: "/.netlify/functions/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Vercel API Routes
    uses: http.get
    with:
      path: "/api/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  # Database as a Service
  - name: MongoDB Atlas Detection
    uses: dns.resolve
    with:
      types: ["CNAME"]
      target: "{{vars.target}}"

  - name: AWS RDS Detection
    uses: dns.resolve
    with:
      types: ["CNAME"]
      target: "{{vars.target}}"

  # Content Delivery Networks
  - name: Akamai CDN Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Fastly CDN Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"

  - name: Azure CDN Detection
    uses: http.headers
    with:
      path: "/"
      scheme: "{{vars.scheme}}"
      timeoutMs: "{{vars.timeout}}"
---

## API and Cloud Service Reconnaissance for {{vars.target}}

This specialized playbook focuses on discovering and analyzing APIs and cloud service configurations including:

### API Discovery

- REST API endpoints and versioning
- GraphQL endpoints and playgrounds
- API documentation (Swagger, OpenAPI, Redoc)

### Cloud Platform Detection

- AWS services (S3, CloudFront, Lambda, API Gateway)
- Azure services and CDN
- Google Cloud Platform services
- CloudFlare and other CDN providers

### Microservices Architecture

- Health check and status endpoints
- Metrics and monitoring endpoints
- Container orchestration indicators
- Service discovery mechanisms

### Authentication & Authorization

- OAuth and OpenID Connect configuration
- SAML metadata endpoints
- JWT key discovery
- Authentication service detection

### API Gateway Detection

- Kong, AWS API Gateway, Zuul
- Rate limiting and proxy headers
- Gateway-specific configurations

### Serverless Platform Detection

- AWS Lambda functions
- Netlify/Vercel serverless functions
- Cloud function endpoints

### Database and Storage Services

- Database-as-a-Service indicators
- Cloud storage bucket detection
- CDN and edge computing services

This playbook helps identify the cloud architecture and API surface area of modern applications.

### Usage

```bash
node ./src/index.js -p ./playbooks/api-cloud-recon.md --var target=api.example.com
```
