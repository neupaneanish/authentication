FROM golang:1.26-alpine AS builder

LABEL authors="neupaneanish"

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o /bin/server ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o /bin/worker ./cmd/worker/main.go

FROM gcr.io/distroless/static-debian12 AS server

WORKDIR /

COPY --from=builder /bin/server /server

USER nonroot:nonroot

ENTRYPOINT ["/server"]

FROM gcr.io/distroless/static-debian12 AS worker

WORKDIR /

COPY --from=builder /bin/worker /worker

USER nonroot:nonroot

ENTRYPOINT ["/worker"]