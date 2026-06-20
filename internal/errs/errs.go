package errs

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrInvalidCredentials     = status.Error(codes.Unauthenticated, "Invalid credentials")
	ErrInvalidTokenOrExpired  = status.Error(codes.Unauthenticated, "Invalid token or expired")
	ErrNotFound               = status.Error(codes.NotFound, "Not found")
	ErrSessionExpired         = status.Error(codes.Aborted, "Session expired")
	ErrInvalidCode            = status.Error(codes.InvalidArgument, "Invalid code")
	ErrInvalidEmail           = status.Error(codes.InvalidArgument, "Invalid email")
	ErrEmailAlreadyExists     = status.Error(codes.AlreadyExists, "Email already exists")
	ErrInvalidPhone           = status.Error(codes.InvalidArgument, "Invalid phone number")
	ErrPhoneAlreadyExists     = status.Error(codes.AlreadyExists, "Phone already exists")
	ErrUsernameAlreadyExists  = status.Error(codes.AlreadyExists, "username already exists")
	ErrAccountAlreadyVerified = status.Error(codes.AlreadyExists, "Account already verified")
	ErrPreviousPassword       = status.Error(codes.AlreadyExists, "Cannot use previously used password")
	ErrAccountRestricted      = status.Error(codes.PermissionDenied, "Account restricted")
	ErrAccountPending         = status.Error(codes.PermissionDenied, "Account not verified")
	ErrInternalServer         = status.Error(codes.Internal, "Internal Server Error")
	ErrRequestTimeout         = status.Error(codes.DeadlineExceeded, "Request timeout exceeded")
	ErrCanceled               = status.Error(codes.Canceled, "Request canceled by client")
	ErrTooManyRequest         = status.Error(codes.ResourceExhausted, "Too many requests rate limit exceeded")
)
