package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/log/global"
)

const (
	timeoutInterval = 5 * time.Second
	metricInterval  = 15 * time.Second
)

func NewTelemetry(
	ctx context.Context,
	url string,
	serviceName string,
	environment string,
) (
	*slog.Logger,
	func(context.Context) error,
	error,
) {
	otel.SetTextMapPropagator(newPropagator())

	res, resErr := newResource(ctx, serviceName, environment)
	if resErr != nil {
		return nil, nil, resErr
	}

	var shutdowns []func(context.Context) error
	shutdown := func(ctx context.Context) error {
		var sErr error
		for _, fn := range slices.Backward(shutdowns) {
			sErr = errors.Join(sErr, fn(ctx))
		}
		return sErr
	}

	handleErr := func(inErr error) error {
		return errors.Join(inErr, shutdown(ctx))
	}

	traceProvider, tpErr := newTracerProvider(ctx, res, url)
	if tpErr != nil {
		return nil, nil, handleErr(tpErr)
	}

	otel.SetTracerProvider(traceProvider)
	shutdowns = append(shutdowns, traceProvider.Shutdown)

	metricProvider, mpErr := newMeterProvider(ctx, res, url)
	if mpErr != nil {
		return nil, nil, handleErr(mpErr)
	}

	otel.SetMeterProvider(metricProvider)
	shutdowns = append(shutdowns, metricProvider.Shutdown)

	loggerProvider, lpErr := newLoggerProvider(ctx, res, url)
	if lpErr != nil {
		return nil, nil, handleErr(lpErr)
	}

	global.SetLoggerProvider(loggerProvider)
	shutdowns = append(shutdowns, loggerProvider.Shutdown)

	logger := otelslog.NewLogger(
		serviceName,
		otelslog.WithLoggerProvider(loggerProvider),
	)

	return logger, shutdown, nil
}
