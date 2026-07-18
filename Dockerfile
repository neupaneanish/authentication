FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

LABEL authors="neupaneanish"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /server ./cmd/server/main.go
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /worker ./cmd/worker/main.go

FROM gcr.io/distroless/static-debian12 AS server

WORKDIR /

COPY --from=builder /server /server

USER nonroot:nonroot

ENTRYPOINT ["/server"]

FROM gcr.io/distroless/static-debian12 AS worker

WORKDIR /

COPY --from=builder /worker /worker

USER nonroot:nonroot

ENTRYPOINT ["/worker"]