module neupaneanish.com.np/authentication

go 1.27.1

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2
	buf.build/go/protovalidate v1.4.0
	github.com/AfterShip/email-verifier v1.5.0
	github.com/MicahParks/jwkset v0.11.3
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/golang-migrate/migrate/v4 v4.20.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.3.4
	github.com/jackc/pgerrcode v0.0.0-20250907135507-afb5586c32a6
	github.com/jackc/pgx/v5 v5.11.0
	github.com/nyaruka/phonenumbers/v2 v2.0.12
	github.com/pquerna/otp v1.5.0
	github.com/stretchr/testify v1.12.1
	github.com/testcontainers/testcontainers-go v0.44.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.44.0
	github.com/testcontainers/testcontainers-go/modules/redpanda v0.44.0
	github.com/testcontainers/testcontainers-go/modules/valkey v0.44.0
	github.com/twmb/franz-go v1.22.0
	github.com/twmb/franz-go/pkg/kadm v1.19.0
	github.com/valkey-io/valkey-go v1.0.78
	github.com/valkey-io/valkey-go/om v1.0.78
	github.com/valkey-io/valkey-go/valkeylimiter v1.0.78
	github.com/valkey-io/valkey-go/valkeyotel v1.0.78
	go.opentelemetry.io/contrib/bridges/otelslog v0.20.1
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.71.0
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.22.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.46.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0
	go.opentelemetry.io/otel/log v0.22.0
	go.opentelemetry.io/otel/sdk v1.46.0
	go.opentelemetry.io/otel/sdk/log v0.22.0
	go.opentelemetry.io/otel/sdk/metric v1.46.0
	golang.org/x/crypto v0.57.0
	golang.org/x/sync v0.23.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	cel.dev/cel-go v0.32.0 // indirect
	cel.dev/expr v0.25.3 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20260917205352-e937bb47801a // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/boombuler/barcode v1.1.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.2.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/cpuguy83/dockercfg v0.3.2 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.8.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/ebitengine/purego v0.11.1 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.31.0 // indirect
	github.com/hbollon/go-edlib v1.7.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/lib/pq v1.12.3 // indirect
	github.com/lufia/plan9stats v0.0.0-20260802145828-341c2f0c90b5 // indirect
	github.com/magiconair/properties v1.18.12 // indirect
	github.com/mdelapenya/tlscert v0.2.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/go-archive v0.3.3 // indirect
	github.com/moby/moby/api v1.56.0 // indirect
	github.com/moby/moby/client v0.6.0 // indirect
	github.com/moby/patternmatcher v0.6.1 // indirect
	github.com/moby/sys/sequential v0.7.0 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.2.1 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/oklog/ulid/v2 v2.1.2 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.30 // indirect
	github.com/power-devops/perfstat v0.0.0-20260916203055-22a1a467d9f0 // indirect
	github.com/shirou/gopsutil/v4 v4.26.8 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.14.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260921155816-b14227669459 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260921155816-b14227669459 // indirect
)
