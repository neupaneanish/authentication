package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	authenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/common/authentication/v1"

	"neupaneanish.com.np/authentication/internal/enum"
	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/repository"
	"neupaneanish.com.np/authentication/internal/utils"
)

//nolint:funlen
func (s *ExternalAuthenticationService) Login(
	ctx context.Context,
	req *externalAuthenticationv1.LoginRequest,
) (*externalAuthenticationv1.LoginResponse, error) {
	serviceName := "Login"
	email := req.GetEmail()

	result, resultErr := s.cfg.RateLimiter.Login.Allow(ctx, email)
	if limiterErr := LimiterCheck(ctx, &result, resultErr, serviceName, email, s.cfg.Logger); limiterErr != nil {
		return nil, limiterErr
	}

	row, rowErr := s.cfg.Repository.Login(ctx, &repository.LoginParams{Email: email})
	if rowErr != nil {
		if errors.Is(rowErr, pgx.ErrNoRows) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "email", email)
			return nil, errs.ErrInvalidCredentials
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", rowErr)
		return nil, errs.ErrInternalServer
	}

	tokenSession := utils.GenerateToken(utils.SessionExpiry)

	if row.Status == enum.UserStatusPending && row.EmailVerifiedAt == nil {
		s.cfg.Logger.WarnContext(ctx, serviceName+" account not verified", "email", email)
		if !utils.ComparePassword(row.Password, req.GetPassword().GetValue()) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" invalid password", "email", email)
			return nil, errs.ErrInvalidCredentials
		}

		if err := s.verification(
			ctx,
			row.ID,
			row.Role,
			row.Username,
			row.Email,
			serviceName,
			tokenSession,
			enum.MethodLogin,
			enum.VerificationMethodAccount,
			row.TwoFactor,
		); err != nil {
			return nil, err
		}

		return &externalAuthenticationv1.LoginResponse{
			Response: &externalAuthenticationv1.LoginResponse_Verification{
				Verification: externalVerification(
					tokenSession,
					externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_ACCOUNT,
				),
			},
		}, nil
	}

	switch row.Status {
	case enum.UserStatusActive:
		break
	case enum.UserStatusPending:
		s.cfg.Logger.WarnContext(ctx, serviceName+" account pending", "email", email)
		return nil, errs.ErrAccountPending
	case enum.UserStatusLocked, enum.UserStatusDisabled, enum.UserStatusSuspended:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return nil, errs.ErrAccountRestricted
	case enum.UserStatusArchived, enum.UserStatusDeleted:
		s.cfg.Logger.WarnContext(ctx, serviceName+" Account "+string(row.Status), "email", email, "status", row.Status)
		return nil, errs.ErrInvalidCredentials
	}

	if !utils.ComparePassword(row.Password, req.GetPassword().GetValue()) {
		s.cfg.Logger.WarnContext(ctx, serviceName+" invalid password", "email", email)
		return nil, errs.ErrInvalidCredentials
	}

	if row.EmailVerifiedAt == nil {
		if err := s.verification(
			ctx,
			row.ID,
			row.Role,
			row.Username,
			row.Email,
			serviceName,
			tokenSession,
			enum.MethodLogin,
			enum.VerificationMethodEmail,
			row.TwoFactor,
		); err != nil {
			return nil, err
		}
		return &externalAuthenticationv1.LoginResponse{
			Response: &externalAuthenticationv1.LoginResponse_Verification{
				Verification: externalVerification(
					tokenSession,
					externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_EMAIL,
				),
			},
		}, nil
	}

	if row.TwoFactor {
		if err := s.verification(
			ctx,
			row.ID,
			row.Role,
			row.Username,
			row.Email,
			serviceName,
			tokenSession,
			enum.MethodLogin,
			enum.VerificationMethodTwoFactor,
			row.TwoFactor,
		); err != nil {
			return nil, err
		}
		return &externalAuthenticationv1.LoginResponse{
			Response: &externalAuthenticationv1.LoginResponse_Verification{
				Verification: externalVerification(
					tokenSession,
					externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_TWO_FACTOR,
				),
			},
		}, nil
	}

	token, tokenErr := login(
		ctx,
		row.ID.String(),
		string(row.Role),
		row.Username,
		serviceName,
		s.cfg.Client,
		s.cfg.Logger,
	)
	if tokenErr != nil {
		return nil, tokenErr
	}

	return &externalAuthenticationv1.LoginResponse{
		Response: &externalAuthenticationv1.LoginResponse_Session{
			Session: &authenticationv1.Session{
				Session: token.Session,
				Expires: timestamppb.New(token.Expires),
			},
		},
	}, nil
}
