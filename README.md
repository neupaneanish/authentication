# Portfolio API

###### Developed by [Anish Neupane](https://neupaneanish.com.np)

--- 

## Overview

Distributed portfolio API with Go, gRPC, PostgreSQL, and Valkey.

---

## Features

- gRPC APIs
- Protocol Buffers (buf.build)
- SQLc query
- JWT authentication
- TOTP based 2FA
- PostgreSQL Database
- Valkey for caching
- Rate Limiter
- OpenTelemetry observability
- Dockerized testing (testcontainers)
- Benchmarks

---

## Technologies Stack

![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![gRPC](https://img.shields.io/badge/gRPC-2596BE?style=for-the-badge&logo=trpc&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Jsonwebtokens](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Valkey](https://img.shields.io/badge/Valkey-FF4438?style=for-the-badge&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![GitHubActions](https://img.shields.io/badge/Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Opentelemetry](https://img.shields.io/badge/Opentelemetry-000000?style=for-the-badge&logo=opentelemetry&logoColor=white)

---

## Endpoints

- [X] Login
- [X] Login Two Factor
- [X] Forget Password
- [X] Verification
- [X] Reset Password

---

## Environments

| Name           | Default                   | Options                            |
|:---------------|:--------------------------|:-----------------------------------|
| DATABASE_URL   |                           |                                    |
| VALKEY_URL     |                           |                                    |
| JWT_KEY        |                           | `ed25519` Private Key Seed Size 32 |
| TWO_FACTOR_KEY |                           | `ed25519` Private Key Seed Size 32 |
| ISSUER         | `Anish Neupane`           |                                    |
| PORT           | `50051`                   | `80` to `65535`                    |
| SERVICE_NAME   | `neupaneanish.com.np/api` |                                    |
| ENVIRONMENT    | `development`             | `development` or `production`      |
| TELEMETRY_URL  |                           | gRPC port only                     |

```dotenv
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/api?sslmode=disable
VALKEY_URL=127.0.0.1:6379
JWT_KEY=
TWO_FACTOR_KEY=
ISSUER='Anish Neupane'
PORT=50051
SERVICE_NAME=neupaneanish.com.np/api
ENVIRONMENT=development
TELEMETRY_URL=127.0.0.1:4317
```

---

## Flow Chart

### Login

```mermaid
flowchart TD
    A[Login] --> B{Enabled 2FA?}
    B -->|No| E[Token]
    B -->|Yes| C{Method}
    C -->|TOTP| D[Validate TOTP]
    C -->|Recovery| F[Validate Recovery Code]
    D --> E
    F --> E
```

---

## Setup, Execution & Testing

```bash
# 1. Clone the core framework engine
git clone https://github.com/neupaneanish/api.git
cd api

# 2. Initialize Git submodules
# (Note: if HTTP use git config --global url."https://github.com/".insteadOf "git@github.com:")
git submodule update --init

# 3. Generate Go code from protobuf definitions (Requires Buf CLI)
buf generate

# 4. Generate Go code from SQL queries using SQLc (Requires SQLc CLI)
sqlc generate

# 5. Execute the tests
go test -v -tags=unit ./...
go test -v -tags=integration ./...
go test -v -tags=benchmark ./...

# 6. Launch the local microservice API server
# (Note: Requires an active OpenTelemetry collector instance, e.g., SigNoz)
go run cmd/server/main.go
```

---

## Application-Layer Rate Limiting Matrix

> Note: For IP will use envoy in future

| Endpoint         | Key               |
|------------------|-------------------|
| Login            | Email             |
| Login Two Factor | Session + User ID |
| Forget Password  | Email             |
| Verification     | Session           |
| Reset Password   | Session           |

---

## Testing Architecture (Testcontainers)

This repository uses a modern, completely containerized testing environment:

- **Integration Tests:** Used real database, valkey and telemetry instances for integration
  tests.
- **Benchmark Tests:** Used memory server i.e. `bufconn` instead of real server for tests.

---

## Performance & Profiling

Benchmarks were executed on:

- OS: Ubuntu Linux (WSL)
- Architecture: amd64
- CPU: Intel® Core™ i7-10750H @ 2.60GHz (12 Execution Threads)

### Benchmarks (Parallel)

Used Bcrypt **(Default Cost)** to secure passwords. To see how well this gRPC server scales under heavy traffic, ran
a benchmark. Seed user **before** benchmark and used **ResetTimer** for real data.

| Endpoints        | Size | Latency (ns/op) | Memory (B/op) | Heap (allocs/op) | Cryptographic Passes         |
|------------------|------|-----------------|---------------|------------------|------------------------------|
| Login            | 195  | 6519490         | 65418         | 595              | 1                            |
| Login Two Factor | N/A  | N/A             | N/A           | N/A              | 0 (TOTP) / Max 10 (Recovery) |
| Forget Password  | N/A  | N/A             | N/A           | N/A              | 0                            |
| Verification     | N/A  | N/A             | N/A           | N/A              | 0                            |
| Reset Password   | 99   | 13423608        | 56968         | 539              | 2 (Max 6)                    |

#### Security Architecture Notes:

- **Login:** 1 Bcrypt operation baseline (utilizes `CompareHashAndPassword` to verify the incoming credentials against
  the database record).
- **Login Two Factor:** Execution cost depends on the validation type:
    - **TOTP:** Uses 0 Bcrypt operations, relying strictly on fast, time-base SHA-1 HMAC
    - **Recovery Code:** 1 Bcrypt operation baseline `CompareHashAndPassword` upto 10 operation depend upon Recovery
      codes length.
- **Reset Password:** 2 Bcrypt operations baseline (1 `CompareHashAndPassword` to verify the active identity context + 1
  `GenerateFromPassword` to securely hash the new replacement credentials). If a user has a fully populated password
  history, the endpoint dynamically invokes up to 4 additional historical comparisons to prevent credential reuse,
  scaling total passes to a maximum of 6.

#### CPU Profile Graph

This execution chart was exported using `go tool pprof` during a standard benchmark run:

![Login CPU Benchmark Image](docs/images/bench_login_cpu.svg)

[Login CPU Benchmark Image](docs/images/bench_login_cpu.svg)

![Reset Password CPU Benchmark Image](docs/images/bench_reset_password_cpu.svg)

[Reset Password CPU Benchmark Image](docs/images/bench_reset_password_cpu.svg)

---

## [License](LICENSE)