package httpserver

import (
	"net/http"
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
	store  store.Store
	auth   *auth.Manager
	router *gin.Engine
}

func New(st store.Store, authMgr *auth.Manager) *Server {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	s := &Server{store: st, auth: authMgr, router: r}
	s.registerRoutes()
	return s
}

func (s *Server) Run(addr string) error {
	log.Info().Str("addr", addr).Msg("HTTP server starting")
	return s.router.Run(addr)
}

func (s *Server) registerRoutes() {
	api := s.router.Group("/api/v1")

	api.GET("/health", s.health)

	auth := api.Group("/", s.authMiddleware())

	// Peers
	auth.GET("/peers", s.listPeers)
	auth.DELETE("/peers/:key", s.deletePeer)

	// Setup keys
	auth.GET("/setup-keys", s.listSetupKeys)
	auth.POST("/setup-keys", s.createSetupKey)
	auth.DELETE("/setup-keys/:id", s.deleteSetupKey)
}

func (s *Server) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) listPeers(c *gin.Context) {
	claims := claimsFromCtx(c)
	peers, err := s.store.GetPeersByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"peers": peers})
}

func (s *Server) deletePeer(c *gin.Context) {
	key := c.Param("key")
	if err := s.store.DeletePeer(c.Request.Context(), key); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *Server) listSetupKeys(c *gin.Context) {
	claims := claimsFromCtx(c)
	keys, err := s.store.GetSetupKeysByAccount(c.Request.Context(), claims.AccountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	expiry := 365 * 24 * time.Hour
	if req.ExpiresIn > 0 {
		expiry = time.Duration(req.ExpiresIn) * 24 * time.Hour
	}

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
