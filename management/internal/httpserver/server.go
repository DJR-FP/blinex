package httpserver

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/meshnet/management/internal/auth"
	"github.com/meshnet/management/internal/domain"
	"github.com/meshnet/management/internal/store"
	"github.com/rs/zerolog/log"
)

type Server struct {
	store   store.Store
	auth    *auth.Manager
	router  *gin.Engine
	notify  func(accountID string) // triggers gRPC sync push to all account peers
	version string
}

func New(st store.Store, authMgr *auth.Manager, notify func(string), version string) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	allowedOrigins := parseOrigins(os.Getenv("MGMT_ALLOWED_ORIGINS"))
	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	s := &Server{store: st, auth: authMgr, router: r, notify: notify, version: version}
	s.registerRoutes()
	return s
}

func (s *Server) Run(addr string, tlsCfg *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("TLS listen on %s: %w", addr, err)
	}
	log.Info().Str("addr", addr).Msg("HTTPS server starting")
	srv := &http.Server{
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return srv.Serve(ln)
}

func (s *Server) registerRoutes() {
	api := s.router.Group("/api/v1")

	api.GET("/health", s.health)

	auth := api.Group("/", s.authMiddleware())

	// Peers
	auth.GET("/peers", s.listPeers)
	auth.DELETE("/peers/:key", s.deletePeer)
	auth.PUT("/peers/:key/routes", s.setPeerRoutes)

	// Setup keys
	auth.GET("/setup-keys", s.listSetupKeys)
	auth.POST("/setup-keys", s.createSetupKey)
	auth.DELETE("/setup-keys/:id", s.deleteSetupKey)

	// Access control rules
	auth.GET("/rules", s.listRules)
	auth.POST("/rules", s.createRule)
	auth.PUT("/rules/:id", s.updateRule)
	auth.DELETE("/rules/:id", s.deleteRule)
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": s.version})
}

func (s *Server) listPeers(c *gin.Context) {
	claims := claimsFromCtx(c)
	peers, err := s.store.GetPeersByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		log.Error().Err(err).Msg("listPeers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

func (s *Server) deletePeer(c *gin.Context) {
	key := c.Param("key")
	claims := claimsFromCtx(c)
	peer, err := s.store.GetPeer(c.Request.Context(), key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
		return
	}
	if peer.AccountID != claims.AccountID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}
	if err := s.store.DeletePeer(c.Request.Context(), key); err != nil {
		log.Error().Err(err).Msg("deletePeer")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	s.auth.RevokeByWGKey(key)
	c.Status(http.StatusNoContent)
}

func (s *Server) setPeerRoutes(c *gin.Context) {
	var req struct {
		Routes []string `json:"routes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, meshNet, _ := net.ParseCIDR("100.64.0.0/10")
	for _, r := range req.Routes {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid CIDR: " + r})
			return
		}
		// Reject routes that would overlap with or contain the mesh CIDR to prevent loops.
		if meshNet != nil && (meshNet.Contains(cidr.IP) || cidr.Contains(meshNet.IP)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "route " + r + " conflicts with mesh CIDR 100.64.0.0/10"})
			return
		}
	}

	key := c.Param("key")
	claims := claimsFromCtx(c)

	peer, err := s.store.GetPeer(c.Request.Context(), key)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
		return
	}
	if peer.AccountID != claims.AccountID {
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	}

	peer.AdvertisedRoutes = req.Routes
	if err := s.store.SavePeer(c.Request.Context(), peer); err != nil {
		log.Error().Err(err).Msg("setPeerRoutes save")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if s.notify != nil {
		s.notify(peer.AccountID)
	}

	c.JSON(http.StatusOK, gin.H{"peer": peer})
}

func (s *Server) listSetupKeys(c *gin.Context) {
	claims := claimsFromCtx(c)
	keys, err := s.store.GetSetupKeysByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		log.Error().Err(err).Msg("listSetupKeys")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"setup_keys": keys})
}

func (s *Server) createSetupKey(c *gin.Context) {
	var req struct {
		Name      string `json:"name" binding:"required"`
		Ephemeral bool   `json:"ephemeral"`
		ExpiresIn int    `json:"expires_in_days"` // 0 = 365 days
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims := claimsFromCtx(c)
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 || expiresIn > 365 {
		expiresIn = 365
	}
	expiry := time.Duration(expiresIn) * 24 * time.Hour

	sk := &domain.SetupKey{
		ID:        uuid.NewString(),
		AccountID: claims.AccountID,
		Key:       uuid.NewString(), // random secret token
		Name:      req.Name,
		Ephemeral: req.Ephemeral,
		ExpiresAt: time.Now().Add(expiry),
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateSetupKey(c.Request.Context(), sk); err != nil {
		log.Error().Err(err).Msg("createSetupKey")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"setup_key": sk})
}

func (s *Server) deleteSetupKey(c *gin.Context) {
	claims := claimsFromCtx(c)
	id := c.Param("id")
	if err := s.store.DeleteSetupKey(c.Request.Context(), claims.AccountID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

var validProtocols = map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}

func validateRuleFields(src, dst, protocol string, port int) error {
	for label, val := range map[string]string{"src": src, "dst": dst} {
		if val == "*" {
			continue
		}
		if net.ParseIP(val) == nil {
			if _, _, err := net.ParseCIDR(val); err != nil {
				return fmt.Errorf("%s must be '*', a valid IP, or a CIDR", label)
			}
		}
	}
	if !validProtocols[strings.ToLower(protocol)] {
		return fmt.Errorf("protocol must be one of: tcp, udp, icmp, all")
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("port must be 0–65535")
	}
	return nil
}

func (s *Server) listRules(c *gin.Context) {
	claims := claimsFromCtx(c)
	rules, err := s.store.GetRulesByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		log.Error().Err(err).Msg("listRules")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rules": rules})
}

func (s *Server) createRule(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Src      string `json:"src" binding:"required"`
		Dst      string `json:"dst" binding:"required"`
		Protocol string `json:"protocol" binding:"required"`
		Port     int    `json:"port"`
		Action   string `json:"action" binding:"required"`
		Enabled  bool   `json:"enabled"`
		Priority int    `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Action != "allow" && req.Action != "deny" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'allow' or 'deny'"})
		return
	}
	if err := validateRuleFields(req.Src, req.Dst, req.Protocol, req.Port); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims := claimsFromCtx(c)
	rule := &domain.Rule{
		ID:        uuid.NewString(),
		AccountID: claims.AccountID,
		Name:      req.Name,
		Src:       req.Src,
		Dst:       req.Dst,
		Protocol:  req.Protocol,
		Port:      req.Port,
		Action:    req.Action,
		Enabled:   req.Enabled,
		Priority:  req.Priority,
		CreatedAt: time.Now(),
	}
	if err := s.store.SaveRule(c.Request.Context(), rule); err != nil {
		log.Error().Err(err).Msg("createRule")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if s.notify != nil {
		s.notify(claims.AccountID)
	}
	c.JSON(http.StatusCreated, gin.H{"rule": rule})
}

func (s *Server) updateRule(c *gin.Context) {
	id := c.Param("id")
	claims := claimsFromCtx(c)

	rules, err := s.store.GetRulesByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		log.Error().Err(err).Msg("updateRule fetch")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	var existing *domain.Rule
	for _, r := range rules {
		if r.ID == id {
			existing = r
			break
		}
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
		return
	}

	var req struct {
		Name     *string `json:"name"`
		Src      *string `json:"src"`
		Dst      *string `json:"dst"`
		Protocol *string `json:"protocol"`
		Port     *int    `json:"port"`
		Action   *string `json:"action"`
		Enabled  *bool   `json:"enabled"`
		Priority *int    `json:"priority"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Src != nil {
		existing.Src = *req.Src
	}
	if req.Dst != nil {
		existing.Dst = *req.Dst
	}
	if req.Protocol != nil {
		existing.Protocol = *req.Protocol
	}
	if req.Port != nil {
		existing.Port = *req.Port
	}
	if req.Action != nil {
		if *req.Action != "allow" && *req.Action != "deny" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "action must be 'allow' or 'deny'"})
			return
		}
		existing.Action = *req.Action
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}

	if err := validateRuleFields(existing.Src, existing.Dst, existing.Protocol, existing.Port); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.store.SaveRule(c.Request.Context(), existing); err != nil {
		log.Error().Err(err).Msg("updateRule save")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	if s.notify != nil {
		s.notify(claims.AccountID)
	}
	c.JSON(http.StatusOK, gin.H{"rule": existing})
}

func (s *Server) deleteRule(c *gin.Context) {
	id := c.Param("id")
	claims := claimsFromCtx(c)
	if err := s.store.DeleteRule(c.Request.Context(), claims.AccountID, id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if s.notify != nil {
		s.notify(claims.AccountID)
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}
		claims, err := s.auth.ValidateToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

func claimsFromCtx(c *gin.Context) *auth.Claims {
	v, _ := c.Get("claims")
	return v.(*auth.Claims)
}

// parseOrigins splits a comma-separated MGMT_ALLOWED_ORIGINS value.
// Defaults to localhost:3000 when empty (suitable for local development).
func parseOrigins(raw string) []string {
	if raw == "" {
		return []string{"http://localhost:3000", "https://localhost:3000"}
	}
	var out []string
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}
