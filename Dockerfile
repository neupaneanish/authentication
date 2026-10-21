FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

LABEL authors="neupaneanish"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /server ./cmd/server/main.go

FROM gcr.io/distroless/static-debian13 AS server

WORKDIR /

COPY --from=builder /server /server

USER nonroot:nonroot

ENTRYPOINT ["/server"]