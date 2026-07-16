//go:build integration || benchmark || e2e

package service_test

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"neupaneanish.com.np/authentication/internal/config"
	"neupaneanish.com.np/authentication/internal/enum"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	gatewayAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/gateway/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/service"
	"neupaneanish.com.np/authentication/internal/telemetry"
	"neupaneanish.com.np/authentication/internal/transport"
	"neupaneanish.com.np/authentication/internal/utils"
	"neupaneanish.com.np/authentication/tests"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"

	// Register the file source driver for migrations.
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var (
	cfg                                 *config.Config
	externalAuthenticationServiceClient externalAuthenticationv1.AuthenticationServiceClient
	gatewayAuthenticationServiceClient  gatewayAuthenticationv1.AuthenticationServiceClient
	phoneCounter                        atomic.Uint64
)

type container struct {
	dbURL            string
	dbCleanup        func()
	vkURL            string
	vkCleanup        func()
	telemetryURL     string
	telemetryCleanup func()
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	baseLogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	testContainer := setupContainer(baseLogger)

	testEnv := setupEnv(testContainer.dbURL, testContainer.vkURL, baseLogger)

	logger, loggerCleanup, loggerErr := telemetry.NewTelemetry(
		ctx,
		testContainer.telemetryURL,
		testEnv.ServiceName,
		testEnv.Environment,
	)

	if loggerErr != nil {
		baseLogger.Error("Failed to start telemetry", "error", loggerErr)
		os.Exit(1)
	}

	testCfg, testCfgErr := config.NewConfig(ctx, testEnv, logger)
	if testCfgErr != nil {
		baseLogger.Error("Failed to setup config", "error", testCfgErr)
		os.Exit(1)
	}

	cfg = testCfg

	client, server, testClientServerErr := testClientServer(testCfg, baseLogger)
	if testClientServerErr != nil {
		baseLogger.Error("Failed to start client / server")
		os.Exit(1)
	}

	externalAuthenticationServiceClient = externalAuthenticationv1.NewAuthenticationServiceClient(client)
	gatewayAuthenticationServiceClient = gatewayAuthenticationv1.NewAuthenticationServiceClient(client)

	code := m.Run()
	loggerCleanupErr := loggerCleanup(ctx)
	if loggerCleanupErr != nil {
		baseLogger.Error("Failed to cleanup logger", "error", loggerCleanupErr)
		os.Exit(1)
	}

	err := client.Close()
	if err != nil {
		baseLogger.Error("Failed to close client", "error", err)
		os.Exit(1)
	}
	server.GracefulStop()
	testContainer.dbCleanup()
	testContainer.vkCleanup()
	testContainer.telemetryCleanup()

	os.Exit(code)
}

func setupContainer(logger *slog.Logger) *container {
	dbURL, dbCleanup, dbErr := tests.Postgres()
	if dbErr != nil {
		logger.Error("Failed to start postgres container", "error", dbErr)
		os.Exit(1)
	}

	migrationErr := runMigrations(dbURL)
	if migrationErr != nil {
		logger.Error("Failed to migrations", "error", migrationErr)
		os.Exit(1)
	}

	vkURL, vkCleanup, vkErr := tests.Valkey()
	if vkErr != nil {
		logger.Error("Failed to start valkey container", "error", vkErr)
		os.Exit(1)
	}

	telemetryURL, telemetryCleanup, telemetryErr := tests.OpenTelemetry()
	if telemetryErr != nil {
		logger.Error("Failed to start telemetry container", "error", telemetryErr)
		os.Exit(1)
	}

	return &container{
		dbURL:            dbURL,
		dbCleanup:        dbCleanup,
		vkURL:            vkURL,
		vkCleanup:        vkCleanup,
		telemetryURL:     telemetryURL,
		telemetryCleanup: telemetryCleanup,
	}
}

func setupEnv(db string, vk string, logger *slog.Logger) *config.Env {
	_, jwtPrivate, jwtKeyErr := ed25519.GenerateKey(nil)
	if jwtKeyErr != nil {
		logger.Error("Failed to validate jwtKey", "error", jwtKeyErr)
		os.Exit(1)
	}

	_, tfPrivate, tfKeyErr := ed25519.GenerateKey(nil)
	if tfKeyErr != nil {
		logger.Error("Failed to validate tfKey", "error", tfKeyErr)
		os.Exit(1)
	}

	return &config.Env{
		DatabaseURL:  db,
		ValkeyURL:    vk,
		JWTKey:       hex.EncodeToString(jwtPrivate.Seed()),
		TwoFactorKey: hex.EncodeToString(tfPrivate.Seed()),
		Issuer:       "Test",
		Environment:  "test",
		ServiceName:  "Test",
		Domain:       "api.neupaneanish.com.np",
	}
}

func testClientServer(cfg *config.Config, logger *slog.Logger) (*grpc.ClientConn, *grpc.Server, error) {
	listen := bufconn.Listen(1024 * 1024)

	opts, optsErr := transport.NewOptions(cfg)

	if optsErr != nil {
		return nil, nil, optsErr
	}

	server := grpc.NewServer(opts...)

	externalAuthenticationv1.RegisterAuthenticationServiceServer(server, service.NewExternalAuthenticationService(cfg))
	gatewayAuthenticationv1.RegisterAuthenticationServiceServer(server, service.NewGatewayAuthenticationService(cfg))

	go func() {
		if err := server.Serve(listen); err != nil {
			logger.Error("Failed to serve server", "error", err)
			os.Exit(1)
		}
	}()

	client, clientErr := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listen.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if clientErr != nil {
		return nil, nil, clientErr
	}

	return client, server, nil
}

func runMigrations(url string) error {
	_, b, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(b), "..", "..")
	migrationsPath := filepath.Join(root, "database", "authentication/migrations")

	db, dbErr := sql.Open("postgres", url)
	if dbErr != nil {
		return dbErr
	}

	defer func() {
		_ = db.Close()
	}()

	driver, driverErr := postgres.WithInstance(db, &postgres.Config{})
	if driverErr != nil {
		return driverErr
	}

	m, mErr := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"postgres",
		driver,
	)
	if mErr != nil {
		return mErr
	}

	defer func() {
		_, _ = m.Close()
	}()

	upErr := m.Up()
	if upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
		return upErr
	}

	return nil
}

func seedUser(ctx context.Context, email string, password string, status enum.UserStatus, active bool) (string, error) {
	tx, txErr := cfg.Pool.Begin(ctx)
	if txErr != nil {
		return "", txErr
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	id := phoneCounter.Add(1)
	phone := fmt.Sprintf("+1571%07d", 5000000+id)

	qtx := repository.New(tx)

	userParams := &repository.CreateUserParams{
		Email:     email,
		Username:  email,
		Phone:     phone,
		Role:      enum.UserRoleUser,
		Status:    status,
		CreatedBy: uuid.Nil,
		UpdatedBy: uuid.Nil,
	}
	userRow, userRowErr := qtx.CreateUser(ctx, userParams)
	if userRowErr != nil {
		return "", userRowErr
	}

	hash, hashErr := utils.CreatePassword(password)
	if hashErr != nil {
		return "", hashErr
	}

	credentialsParams := &repository.CreateCredentialParams{
		UserID:    userRow.ID,
		Password:  hash,
		CreatedBy: userRow.ID,
	}

	affected, credentialsErr := qtx.CreateCredential(ctx, credentialsParams)
	if credentialsErr != nil {
		return "", credentialsErr
	}

	if affected.RowsAffected() == 0 {
		return "", errors.New("cannot create credentials")
	}

	if active {
		verifyEmailParams := &repository.VerifyEmailParams{
			Status:    enum.UserStatusActive,
			UpdatedBy: userRow.ID,
			ID:        userRow.ID,
		}

		_, userErr := qtx.VerifyEmail(ctx, verifyEmailParams)
		if userErr != nil {
			return "", userErr
		}
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		return "", txCommitErr
	}

	return userRow.ID.String(), nil
}

func contextWithValue(t *testing.T, userID string) context.Context {
	t.Helper()

	md := metadata.Pairs(
		"x-user-id", userID,
		"x-role", "test",
		"x-jti", uuid.NewString(),
	)

	ctx := metadata.NewOutgoingContext(t.Context(), md)
	return ctx
}
