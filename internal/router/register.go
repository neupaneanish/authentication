package router

func (s *HTTPServer) register() {
	s.mux.HandleFunc("/.well-known/jwks.json", s.jwt.Jwks)

	s.mux.HandleFunc("/health", s.health)
}
