package service

import (
	"context"
	"crypto/rand"
	"time"

	"uuid"

	"github.com/valkey-io/valkey-go/om"
	"github.com/valkey-io/valkey-go/valkeylimiter"
	"google.golang.org/protobuf/types/known/timestamppb"

	"neupaneanish.com.np/authentication/internal/repository"

	"neupaneanish.com.np/authentication/internal/enum"

	"neupaneanish.com.np/authentication/internal/errs"
	externalAuthenticationv1 "neupaneanish.com.np/authentication/internal/protobuf/external/authentication/v1"
	"neupaneanish.com.np/authentication/internal/redis"
	"neupaneanish.com.np/authentication/internal/utils"
)

func (s *ExternalAuthenticationService) Verification(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
) (*externalAuthenticationv1.VerificationResponse, error) {
	serviceName := "Verification"
	session := req.GetSession()

	verificationSession, verificationSessionErr := s.verificationLimiterCheck(ctx, session, serviceName)
	if verificationSessionErr != nil {
		return nil, verificationSessionErr
	}

	userID, userIDErr := uuid.Parse(verificationSession.UserID)
	if userIDErr != nil {
		s.deleteVerificationSession(ctx, session, serviceName)
		s.cfg.Logger.ErrorContext(
			ctx,
			"Invalid UserID",
			"service", serviceName,
			"userID", verificationSession.UserID,
			"error", userIDErr,
		)
		return nil, errs.ErrSessionExpired
	}

	if !enum.UserRole(verificationSession.Role).Valid() {
		s.deleteVerificationSession(ctx, session, serviceName)
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Role",
			"service", serviceName,
			"role", verificationSession.Role,
		)
		return nil, errs.ErrSessionExpired
	}

	switch enum.Method(verificationSession.Method) {
	case enum.MethodLogin:
		switch enum.VerificationMethod(verificationSession.VerificationMethod) {
		case enum.VerificationMethodAccount, enum.VerificationMethodEmail:
			if verificationSession.EnabledTwoFactor {
				if err := s.validateVerificationCodeEmail(ctx, req, verificationSession, serviceName); err != nil {
					return nil, err
				}
				newSession := rand.Text()
				if err := s.verification(
					ctx,
					userID,
					enum.UserRole(verificationSession.Role),
					verificationSession.Email,
					newSession,
					serviceName,
					enum.MethodLogin,
					enum.VerificationMethodTwoFactor,
					false,
				); err != nil {
					return nil, err
				}
				s.deleteVerificationSession(ctx, session, serviceName)
				return &externalAuthenticationv1.VerificationResponse{
					Response: &externalAuthenticationv1.VerificationResponse_Verification{
						Verification: externalVerification(
							newSession,
							externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_TWO_FACTOR,
						),
					},
				}, nil
			}
			return s.verificationEmailLogin(ctx, req, verificationSession, userID, serviceName)
		case enum.VerificationMethodTwoFactor:
			return s.verificationTwoFactor(ctx, req, verificationSession, userID, serviceName)
		default:
			s.cfg.Logger.WarnContext(
				ctx,
				"Invalid Verification Method",
				"service", serviceName,
				"method", verificationSession.Method,
				"verificationMethod", verificationSession.VerificationMethod,
			)
			s.deleteVerificationSession(ctx, session, serviceName)
			return nil, errs.ErrSessionExpired
		}
	case enum.MethodForgetPassword:
		return s.verificationForgetPassword(ctx, req, verificationSession, userID, serviceName)
	case enum.MethodRegister:
		return s.verificationRegister(ctx, req, verificationSession, userID, serviceName)
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Method",
			"service", serviceName,
			"method", verificationSession.Method,
		)
		s.deleteVerificationSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
	}
}

func (s *ExternalAuthenticationService) verificationLimiterCheck(
	ctx context.Context,
	session,
	serviceName string,
) (*utils.VerificationSession, error) {
	var result valkeylimiter.Result
	var resultErr error

	result, resultErr = s.cfg.RateLimiter.Verification.Allow(ctx, session)
	if err := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		session,
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}

	verificationSession, verificationSessionErr := redis.HGet[utils.VerificationSession](
		ctx,
		utils.VerificationSessionPrefix,
		session,
		s.cfg.Client,
	)
	if verificationSessionErr != nil {
		if om.IsRecordNotFound(verificationSessionErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" not found", "session", session)
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey get", "error", verificationSessionErr)
		return nil, errs.ErrInternalServer
	}

	switch enum.VerificationMethod(verificationSession.VerificationMethod) {
	case enum.VerificationMethodAccount:
		result, resultErr = s.cfg.RateLimiter.VerificationAccount.Allow(ctx, verificationSession.UserID)
	case enum.VerificationMethodEmail:
		result, resultErr = s.cfg.RateLimiter.VerificationEmail.Allow(ctx, verificationSession.UserID)
	case enum.VerificationMethodReset:
		result, resultErr = s.cfg.RateLimiter.VerificationReset.Allow(ctx, verificationSession.UserID)
	case enum.VerificationMethodTwoFactor:
		result, resultErr = s.cfg.RateLimiter.VerificationTwoFactor.Allow(ctx, verificationSession.UserID)
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Verification Method",
			"service", serviceName,
			"method", verificationSession.Method,
			"verificationMethod", verificationSession.VerificationMethod,
		)
		s.deleteVerificationSession(ctx, session, serviceName)
		return nil, errs.ErrSessionExpired
	}
	if err := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		verificationSession.UserID,
		s.cfg.Logger,
	); err != nil {
		return nil, err
	}
	return verificationSession, nil
}

func (s *ExternalAuthenticationService) verificationEmailLogin(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
	verificationSession *utils.VerificationSession,
	userID uuid.UUID,
	serviceName string,
) (*externalAuthenticationv1.VerificationResponse, error) {
	if err := s.validateVerificationCodeEmail(ctx, req, verificationSession, serviceName); err != nil {
		return nil, err
	}
	if err := s.verificationVerifyAccountEmail(
		ctx,
		userID,
		verificationSession.Key,
		serviceName,
	); err != nil {
		return nil, err
	}
	s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
	return s.verificationLogin(ctx, verificationSession, serviceName)
}

func (s *ExternalAuthenticationService) deleteVerificationSession(
	ctx context.Context,
	session, serviceName string,
) {
	if err := redis.HDelete[utils.VerificationSession](
		ctx,
		utils.VerificationSessionPrefix,
		session,
		s.cfg.Client,
	); err != nil {
		s.cfg.Logger.ErrorContext(ctx, "Verification Session Delete", "service", serviceName, "error", err)
	}
}

func (s *ExternalAuthenticationService) verificationLogin(
	ctx context.Context, verificationSession *utils.VerificationSession, serviceName string,
) (*externalAuthenticationv1.VerificationResponse, error) {
	jwt, jwtErr := s.login(ctx, verificationSession.UserID, verificationSession.Role, serviceName)
	if jwtErr != nil {
		return nil, jwtErr
	}
	s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
	return &externalAuthenticationv1.VerificationResponse{
		Response: &externalAuthenticationv1.VerificationResponse_Token{
			Token: &externalAuthenticationv1.Token{
				Access:   jwt.Access,
				Refresh:  jwt.Refresh,
				ExpireAt: timestamppb.New(jwt.ExpiryAt),
			},
		},
	}, nil
}

func (s *ExternalAuthenticationService) validateVerificationCodeEmail(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
	verificationSession *utils.VerificationSession,
	serviceName string,
) error {
	switch code := req.GetCode().(type) {
	case *externalAuthenticationv1.VerificationRequest_Email:
		if code.Email != verificationSession.Code {
			s.cfg.Logger.WarnContext(
				ctx,
				"Invalid Code",
				"service", serviceName,
				"userID", verificationSession.UserID,
			)
			return errs.ErrInvalidCode
		}
		return nil
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Code type",
			"service", serviceName,
			"Verification Method", verificationSession.VerificationMethod,
			"userID", verificationSession.UserID,
		)
		s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
		return errs.ErrSessionExpired
	}
}

func (s *ExternalAuthenticationService) verificationTwoFactor(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
	verificationSession *utils.VerificationSession,
	userID uuid.UUID,
	serviceName string,
) (*externalAuthenticationv1.VerificationResponse, error) {
	switch code := req.GetCode().(type) {
	case *externalAuthenticationv1.VerificationRequest_Totp:
		if err := ValidateTotpCode(
			ctx,
			userID,
			s.cfg.Repository,
			code.Totp,
			serviceName,
			s.cfg.TwoFactor,
			s.cfg.Logger,
		); err != nil {
			return nil, err
		}
		params := &repository.UpdateTwoFactorParams{UpdatedBy: userID, UserID: userID}
		cmdTag, cmdTagErr := s.cfg.Repository.UpdateTwoFactor(ctx, params)
		if err := AffectedRowCheck(
			ctx,
			cmdTag,
			cmdTagErr,
			"TwoFactor Last Used",
			serviceName,
			1,
			s.cfg.Logger,
		); err != nil {
			return nil, err
		}
		return s.verificationLogin(ctx, verificationSession, serviceName)
	case *externalAuthenticationv1.VerificationRequest_Recovery:
		recoveryID, recoveryErr := ValidateRecoveryCode(
			ctx,
			userID,
			s.cfg.Repository,
			code.Recovery,
			serviceName,
			s.cfg.TwoFactor,
			s.cfg.Logger,
		)
		if recoveryErr != nil {
			return nil, recoveryErr
		}
		params := &repository.UpdateRecoveryCodeParams{ID: recoveryID, UserID: userID}
		cmdTag, cmdTagErr := s.cfg.Repository.UpdateRecoveryCode(ctx, params)
		if err := AffectedRowCheck(
			ctx,
			cmdTag,
			cmdTagErr,
			"Recovery Code Update",
			serviceName,
			1,
			s.cfg.Logger,
		); err != nil {
			return nil, err
		}
		s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
		return s.verificationLogin(ctx, verificationSession, serviceName)
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Code type",
			"service", serviceName,
			"Verification Method", verificationSession.VerificationMethod,
			"userID", verificationSession.UserID,
		)
		s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}
}

func (s *ExternalAuthenticationService) verificationForgetPassword(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
	verificationSession *utils.VerificationSession,
	userID uuid.UUID,
	serviceName string,
) (*externalAuthenticationv1.VerificationResponse, error) {
	session := rand.Text()
	switch enum.VerificationMethod(verificationSession.VerificationMethod) {
	case enum.VerificationMethodAccount,
		enum.VerificationMethodEmail:
		if err := s.validateVerificationCodeEmail(ctx, req, verificationSession, serviceName); err != nil {
			return nil, err
		}
		if err := s.verificationVerifyAccountEmail(ctx, userID, verificationSession.Key, serviceName); err != nil {
			return nil, err
		}
		if err := s.verification(
			ctx,
			userID,
			enum.UserRole(verificationSession.Role),
			verificationSession.Email,
			session,
			serviceName,
			enum.MethodForgetPassword,
			enum.VerificationMethodReset,
			verificationSession.EnabledTwoFactor,
		); err != nil {
			return nil, err
		}
		return &externalAuthenticationv1.VerificationResponse{
			Response: &externalAuthenticationv1.VerificationResponse_Verification{
				Verification: externalVerification(
					session,
					externalAuthenticationv1.VerificationMethod_VERIFICATION_METHOD_RESET,
				),
			},
		}, nil
	case enum.VerificationMethodReset:
		if err := s.validateVerificationCodeEmail(ctx, req, verificationSession, serviceName); err != nil {
			return nil, err
		}
		data := &utils.ResetPasswordSession{
			Key:    session,
			ExAt:   time.Now().Add(utils.SessionExpiry),
			UserID: userID.String(),
			Email:  verificationSession.Email,
		}

		if err := redis.HSet[utils.ResetPasswordSession](
			ctx,
			utils.ResetPasswordSessionPrefix,
			data,
			s.cfg.Client,
		); err != nil {
			s.cfg.Logger.ErrorContext(ctx, "Verification Reset Set", "service", serviceName, "error", err)
			return nil, errs.ErrInternalServer
		}
		return &externalAuthenticationv1.VerificationResponse{
			Response: &externalAuthenticationv1.VerificationResponse_ResetSession{
				ResetSession: &externalAuthenticationv1.ResetSession{Session: session},
			},
		}, nil
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Verification Method",
			"service", serviceName,
			"method", verificationSession.Method,
			"verificationMethod", verificationSession.VerificationMethod,
		)
		return nil, errs.ErrSessionExpired
	}
}

func (s *ExternalAuthenticationService) verificationVerifyAccountEmail(
	ctx context.Context,
	userID uuid.UUID,
	key,
	serviceName string,
) error {
	params := &repository.VerifyEmailParams{
		Status:    enum.UserStatusActive,
		UpdatedBy: uuid.Nil(),
		ID:        userID,
	}

	tag, tagErr := s.cfg.Repository.VerifyEmail(ctx, params)
	if tagErr != nil {
		s.cfg.Logger.ErrorContext(ctx, "Verify Account / Email", "service", serviceName, "error", tagErr)
		return errs.ErrInternalServer
	}

	if tag.RowsAffected() == 0 {
		s.cfg.Logger.WarnContext(
			ctx,
			"Account already verified / account not found",
			"service",
			serviceName,
			"userID", userID.String(),
		)
		s.deleteVerificationSession(ctx, key, serviceName)
		return errs.ErrAccountAlreadyVerified
	}
	return nil
}

func (s *ExternalAuthenticationService) verificationRegister(
	ctx context.Context,
	req *externalAuthenticationv1.VerificationRequest,
	verificationSession *utils.VerificationSession,
	userID uuid.UUID,
	serviceName string,
) (*externalAuthenticationv1.VerificationResponse, error) {
	switch enum.VerificationMethod(verificationSession.VerificationMethod) {
	case enum.VerificationMethodAccount:
		return s.verificationEmailLogin(ctx, req, verificationSession, userID, serviceName)
	default:
		s.cfg.Logger.WarnContext(
			ctx,
			"Invalid Verification Method",
			"service", serviceName,
			"method", verificationSession.Method,
			"verificationMethod", verificationSession.VerificationMethod,
		)
		s.deleteVerificationSession(ctx, verificationSession.Key, serviceName)
		return nil, errs.ErrSessionExpired
	}
}
