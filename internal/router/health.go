package router

import (
	"fmt"
	"net/http"
	"time"
)

func (s *HTTPServer) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	const jsonTemplate = `{"status":"ok","version":"1.0.0","time":"%s"}`

	response := fmt.Sprintf(jsonTemplate, time.Now().UTC().Format(time.RFC3339))

	if _, err := w.Write([]byte(response)); err != nil {
		s.logger.ErrorContext(r.Context(), "failed to write health response", "error", err)
		return
	}
}
