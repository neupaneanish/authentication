package service

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/jackc/pgx/v5"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
)

//nolint:funlen
func (s *ExternalAuthenticationService) ForgetPassword(
	ctx context.Context,
	req *externalAuthenticationv1.ForgetPasswordRequest,
) (*externalAuthenticationv1.ForgetPasswordResponse, error) {
	serviceName := "ForgetPassword"
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.ForgetPassword.Allow(ctx, email)
	if limiterErr := LimiterCheck(ctx, &result, resultErr, serviceName, email, s.cfg.Logger); limiterErr != nil {
		return nil, limiterErr
	}

	session := rand.Text()
	response := &externalAuthenticationv1.ForgetPasswordResponse{
		Verification: externalVerification(
			session,
			externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_RESET,
		),
	}

	if !s.cfg.Domain.ValidateEmail(email) {
		s.cfg.Logger.WarnContext(ctx, "invalid email", "email", email)
		return response, nil
	}

	params := &repository.UserByEmailParams{Email: email}

	row, rowErr := s.cfg.Repository.UserByEmail(ctx, params)
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "email", email)
			return response, nil
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	if row.Status == enum.UserStatusPending && row.EmailVerifiedAt == nil {
		if err := s.verification(
			ctx,
			row.ID,
			row.Role,
			email,
			session,
			serviceName,
			enum.MethodForgetPassword,
			enum.VerificationMethodAccount,
			false,
		); err != nil {
			return nil, err
		}
		return &externalAuthenticationv1.ForgetPasswordResponse{
			Verification: externalVerification(
				session,
				externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_ACCOUNT,
			),
		}, nil
	}

	switch row.Status {
	case enum.UserStatusActive:
		break
	case enum.UserStatusPending:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account pending", "email", email, "status", row.Status)
		return nil, errs.ErrAccountPending
	case enum.UserStatusLocked,
		enum.UserStatusDisabled,
		enum.UserStatusSuspended,
		enum.UserStatusArchived,
		enum.UserStatusDeleted:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return response, nil
	}

	if row.EmailVerifiedAt == nil {
		if err := s.verification(
			ctx,
			row.ID,
			row.Role,
			email,
			session,
			serviceName,
			enum.MethodForgetPassword,
			enum.VerificationMethodEmail,
			false,
		); err != nil {
			return nil, err
		}

		return &externalAuthenticationv1.ForgetPasswordResponse{
			Verification: externalVerification(
				session,
				externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_EMAIL,
			),
		}, nil
	}

	if err := s.verification(
		ctx,
		row.ID,
		row.Role,
		email,
		session,
		serviceName,
		enum.MethodForgetPassword,
		enum.VerificationMethodReset,
		false,
	); err != nil {
		return nil, err
	}

	return response, nil
}
