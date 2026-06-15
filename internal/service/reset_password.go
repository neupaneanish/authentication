package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/valkey-io/valkey-go/om"
	"neupaneanish.com.np/api/internal/errs"
	authv1 "neupaneanish.com.np/api/internal/protobuf/auth/v1"
	"neupaneanish.com.np/api/internal/redis"
	"neupaneanish.com.np/api/internal/repository"
	"neupaneanish.com.np/api/internal/task"
	"neupaneanish.com.np/api/internal/utils"
)

//nolint:funlen
func (s *AuthService) ResetPassword(
	ctx context.Context,
	req *authv1.ResetPasswordRequest,
) (*authv1.ResetPasswordResponse, error) {
	serviceName := "ResetPassword"

	result, resultErr := s.cfg.RateLimiter.ResetPassword.Allow(ctx, req.GetSession())
	if limiterErr := LimiterCheck(
		ctx,
		&result,
		resultErr,
		serviceName,
		req.GetSession(),
		s.cfg.Logger,
	); limiterErr != nil {
		return nil, limiterErr
	}

	resetSession, resetSessionErr := redis.HGet[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		req.GetSession(),
		s.cfg.Client,
	)
	if resetSessionErr != nil {
		if om.IsRecordNotFound(resetSessionErr) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" session expired", "session", req.GetSession())
			return nil, errs.ErrSessionExpired
		}
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey hGet", "error", resetSessionErr)
		return nil, errs.ErrInternalServer
	}

	userID := uuid.MustParse(resetSession.UserID)
	params := &repository.CredentialsParams{UserID: userID, HistoryLimit: utils.CredentialsHistoryLimit}

	passwords, passwordsErr := s.cfg.Repository.Credentials(ctx, params)
	if passwordsErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" database", "error", passwordsErr)
		return nil, errs.ErrInternalServer
	}

	if len(passwords) == 0 {
		s.cfg.Logger.WarnContext(ctx, serviceName+" notfound", "userID", resetSession.UserID)
		return nil, errs.ErrSessionExpired
	}

	for _, hash := range passwords {
		if utils.ComparePassword(hash, req.GetPassword().GetValue()) {
			s.cfg.Logger.WarnContext(ctx, serviceName+" previous used password", "userID", userID)
			return nil, errs.ErrPreviousPassword
		}
	}

	newHash, newHashErr := utils.CreatePassword(req.GetPassword().GetValue())
	if newHashErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" password hash", "error", newHashErr)
		return nil, errs.ErrInternalServer
	}

	credentialParams := &repository.CreateCredentialParams{UserID: userID, Password: newHash, CreatedBy: userID}

	tx, txErr := s.cfg.Pool.Begin(ctx)
	if txErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" transactions", "error", txErr)
		return nil, errs.ErrInternalServer
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	qtx := repository.New(tx)

	credentials, credentialsErr := qtx.CreateCredential(ctx, credentialParams)
	if credentialsErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" create credentials", "error", credentialsErr)
		return nil, errs.ErrInternalServer
	}

	if credentials.RowsAffected() == 0 {
		s.cfg.Logger.WarnContext(ctx, serviceName+" credential not created", "userID", resetSession.UserID)
		return nil, errs.ErrInternalServer
	}

	if txCommitErr := tx.Commit(ctx); txCommitErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" commit", "error", txCommitErr)
		return nil, errs.ErrInternalServer
	}

	t, tErr := task.SecurityNotification(task.TypePasswordReset, resetSession.Email)
	_ = EmailEnqueue(ctx, t, tErr, serviceName, s.cfg.Logger, s.cfg.Worker) // Error already handled by EmailEnqueue

	hDeleteErr := redis.HDelete[utils.ResetPasswordSession](
		ctx,
		utils.ResetPasswordSessionPrefix,
		req.GetSession(),
		s.cfg.Client,
	)
	if hDeleteErr != nil {
		s.cfg.Logger.ErrorContext(ctx, serviceName+" valkey delete", "error", hDeleteErr)
	}

	return &authv1.ResetPasswordResponse{}, nil
}
