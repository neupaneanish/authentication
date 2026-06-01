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
- [ ] Login Two Factor
- [X] Forget Password
- [X] Verification
- [ ] Reset Password

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

## Setup, Execution & Testing

```bash
# 1. Clone the core framework engine
git clone https://gitlab.com/neupaneanish/api.git
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

### Login Endpoint

I use Bcrypt **(Default Cost)** to secure passwords. To see how well this gRPC server scales under heavy traffic, I ran
a benchmark. Seed user **before** benchmark and used **ResetTimer** for real data.

| Run  | Size  | Latency (ns/op) | Memory (B/op) | Heap (allocs/op) |
|:----:|:-----:|:---------------:|:-------------:|:----------------:|
| `1`  | `192` |    `6080764`    |    `58517`    |      `551`       |
| `2`  | `166` |    `6427396`    |    `66771`    |      `595`       |
| `3`  | `178` |    `6211621`    |    `65842`    |      `597`       |
| `4`  | `180` |    `6886280`    |    `65578`    |      `583`       |
| `5`  | `184` |    `6655233`    |    `63855`    |      `567`       |
| `6`  | `196` |    `6399389`    |    `63668`    |      `584`       |
| `7`  | `188` |    `6397436`    |    `66965`    |      `597`       |
| `8`  | `168` |    `6619212`    |    `66441`    |      `581`       |
| `9`  | `151` |    `7266336`    |    `59881`    |      `567`       |
| `10` | `193` |    `6498513`    |    `61332`    |      `552`       |

**Takeaway:** Performance is highly consistent under full load, averaging roughly **6.4 ms per login**. Memory use and
heap allocations stay completely flat, showing the request pipeline is clean and free of memory leaks.

#### CPU Profile Graph

This execution chart was exported using `go tool pprof` during a standard benchmark run:

![Login CPU Benchmark Image](docs/images/bench_login_cpu.svg)

[Login CPU Benchmark Image](docs/images/bench_login_cpu.svg)

---

## [License](LICENSE)