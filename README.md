# Portfolio API

###### Developed by [Anish Neupane](https://neupaneanish.com.np)

--- 

## Overview

Distributed authentication and portfolio management backend with Go, gRPC, PostgreSQL, and Valkey

---

## Features

- gRPC APIs with Protocol Buffers
- JWT authentication
- TOTP based 2FA
- PostgreSQL Database
- Valkey for caching
- OpenTelemetry observability
- Dockerized testing (testcontainers)
- SQLc query

---

## Technologies Stack

![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![gRPC](https://img.shields.io/badge/gRPC-2596BE?style=for-the-badge&logo=trpc&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?style=for-the-badge&logo=postgresql&logoColor=white)
![Jsonwebtokens](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Valkey](https://img.shields.io/badge/Valkey-FF4438?style=for-the-badge&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)
![GitHubActions](https://img.shields.io/badge/Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Opentelemetry](https://img.shields.io/badge/Opentelemetry-000000?style=for-the-badge&logo=opentelemetry&logoColor=white)

---

## Environments

| Name           | Default             | Options                          |
|:---------------|:--------------------|:---------------------------------|
| DATABASE_URL   |                     |                                  |
| VALKEY_URL     |                     |                                  |
| JWT_KEY        |                     | ed25519 Private Key Seed Size 32 |
| TWO_FACTOR_KEY |                     | ed25519 Private Key Seed Size 32 |
| ISSUER         | Anish Neupane       |                                  |
| PORT           | 50051               | 80 to 65535                      |
| SERVICE_NAME   | neupaneanish.com.np |                                  |
| ENVIRONMENT    | development         | development or production        |
| TELEMETRY_URL  |                     | gRPC port only                   |

```dotenv
DATABASE_URL=
VALKEY_URL=
JWT_KEY=
TWO_FACTOR_KEY=
ISSUER=
PORT=
SERVICE_NAME=
ENVIRONMENT=
TELEMETRY_URL=
```

---

## Setup, Execution & Testing

```bash
# 1. Clone the core framework engine
git clone https://gitlab.com/neupaneanish/api.git
cd api

# 2. Initialize Git submodules
git submodule update --init

# 3. Generate Go code from protobuf definitions (Requires Buf CLI)
buf generate

# 4. Generate Go code from SQL queries using SQLc (Requires SQLc CLI)
sqlc generate

# 5. Execute the complete integration test suite
# (Note: Requires a running Docker Engine on your machine for Testcontainers)
go test -v ./...

# 6. Launch the local microservice API server
# (Note: Requires an active OpenTelemetry collector instance, e.g., SigNoz)
go run cmd/server/main.go
```

---

## [License](LICENSE)