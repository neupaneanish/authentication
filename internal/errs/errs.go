package errs

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidCredentials    = status.Error(codes.Unauthenticated, "Invalid credentials")
	ErrInvalidTokenOrExpired = status.Error(codes.Unauthenticated, "Invalid token or expired")
	ErrNotFound              = status.Error(codes.NotFound, "Not found")
	ErrSessionExpired        = status.Error(codes.Aborted, "Session expired")
	ErrInvalidCode           = status.Error(codes.InvalidArgument, "Invalid code")
	ErrPasswordMissMatch     = status.Error(codes.InvalidArgument, "Password miss match")
	ErrPreviousPassword      = status.Error(codes.AlreadyExists, "Cannot use previously used password")
	ErrAccountRestricted     = status.Error(codes.PermissionDenied, "Account restricted")
	ErrAccountPending        = status.Error(codes.PermissionDenied, "Account not verified")
	ErrInternalServer        = status.Error(codes.Internal, "Internal Server Error")
	ErrRequestTimeout        = status.Error(codes.DeadlineExceeded, "Request timeout exceeded")
	ErrCanceled              = status.Error(codes.Canceled, "Request canceled by client")
	ErrTooManyRequest        = status.Error(codes.ResourceExhausted, "Too many requests rate limit exceeded")
)
