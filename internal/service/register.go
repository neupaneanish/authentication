package service

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

//nolint:funlen
func (s *ExternalAuthenticationService) Register(
	ctx context.Context,
	req *externalAuthenticationv1.RegisterRequest,
) (*externalAuthenticationv1.RegisterResponse, error) {
	serviceName := "Register"

	if !s.cfg.Domain.ValidateEmail(req.GetEmail()) {
		s.cfg.Logger.WarnContext(ctx, serviceName+" invalid email", "email", req.GetEmail())
		return nil, errs.ErrInvalidEmail
	}

	phoneNumber, phoneNumberErr := utils.PhoneNumber(req.GetPhone())
	if phoneNumberErr != nil {
		s.cfg.Logger.WarnContext(ctx, serviceName+" invalid phone", "phone", req.GetPhone())
		return nil, errs.ErrInvalidPhone
	}

	hashPassword, hashPasswordErr := utils.CreatePassword(req.GetPassword().GetValue())
	if hashPasswordErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Password hash", "service", serviceName, "error", hashPasswordErr)
		return nil, errs.ErrInternalServer
	}

	userParams := &repository.CreateUserParams{
		Email:     req.GetEmail(),
		Username:  s.cfg.Domain.GenerateUsername(req.GetEmail()),
		Phone:     phoneNumber,
		Role:      enum.UserRoleUser,
		Status:    enum.UserStatusPending,
		CreatedBy: uuid.Nil,
		UpdatedBy: uuid.Nil,
	}

	tx, txErr := s.cfg.Pool.Begin(ctx)
	if txErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "transactions begin", "service", serviceName, "error", txErr)
		return nil, errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	user, userErr := qtx.CreateUser(ctx, userParams)
	if userErr != nil {
		if pgxErr, ok := errors.AsType[*pgconn.PgError](userErr); ok && pgxErr.Code == pgerrcode.UniqueViolation {
			switch pgxErr.ConstraintName {
			case UsersEmailKey:
				s.cfg.Logger.WarnContext(
					ctx,
					"User registration collision: email already exists",
					"service",
					serviceName,
					"email",
					userParams.Email,
				)
				return nil, errs.ErrEmailAlreadyExists
			case UsersPhoneKey:
				s.cfg.Logger.WarnContext(
					ctx,
					"User registration collision: phone already exists",
					"service",
					serviceName,
					"phone",
					userParams.Phone,
				)
				return nil, errs.ErrPhoneAlreadyExists
			default:
				s.cfg.Logger.WarnContext(
					ctx,
					"User registration collision: username already exists",
					"service",
					serviceName,
					"username", userParams.Username,
				)
				return nil, errs.ErrUsernameAlreadyExists
			}
		}
		s.cfg.Logger.ErrorContext(ctx, "Create user failed", "service", serviceName, "error", userErr)
		return nil, errs.ErrInternalServer
	}

	credentials, credentialsErr := qtx.CreateCredential(ctx, &repository.CreateCredentialParams{
		UserID:    user.ID,
		Password:  hashPassword,
		CreatedBy: uuid.Nil,
	})

	if credentialsErr != nil || credentials.RowsAffected() == 0 {
		s.cfg.Logger.ErrorContext(ctx, "Create credentials failed", "service", serviceName, "error", credentialsErr)
		return nil, errs.ErrInternalServer
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Commit", "service", serviceName, "error", txCommitErr)
		return nil, errs.ErrInternalServer
	}

	session := rand.Text()

	emailErr := s.emailVerification(
		ctx,
		serviceName,
		enum.MethodRegister,
		session,
		user.ID.String(),
		string(user.Role),
		false,
		true,
		user.Email,
	)
	if emailErr != nil {
		return nil, emailErr
	}

	return &externalAuthenticationv1.RegisterResponse{Session: session}, nil
}
