package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/blinex/management/internal/domain"
	"github.com/blinex/management/internal/store"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// models —————————————————————————————————————————————————————————————————————

type account struct {
	ID        string    `gorm:"primaryKey"`
	Name      string
	CreatedAt time.Time
}

type setupKey struct {
	ID        string `gorm:"primaryKey"`
	AccountID string `gorm:"index"`
	Key       string `gorm:"uniqueIndex"`
	Name      string
	Ephemeral bool
	UsedCount int
	ExpiresAt time.Time
	CreatedAt time.Time
}

type peer struct {
	ID               string    `gorm:"primaryKey"`
	AccountID        string    `gorm:"index"`
	WGPubKey         string    `gorm:"uniqueIndex"`
	IP               string
	Hostname         string
	OS               string
	Kernel           string
	DNSLabel         string
	Tags             string // comma-separated
	AllowedIPs       string // comma-separated
	AdvertisedRoutes string // comma-separated CIDRs
	Connected        bool
	LastSeen         time.Time
	CreatedAt        time.Time
}

type rule struct {
	ID        string    `gorm:"primaryKey"`
	AccountID string    `gorm:"index"`
	Name      string
	Src       string
	Dst       string
	Protocol  string
	Port      int
	Action    string
	Enabled   bool
	Priority  int
	CreatedAt time.Time
}

// Store ———————————————————————————————————————————————————————————————————————

// Store is a PostgreSQL-backed implementation of store.Store.
type Store struct {
	db *gorm.DB
}

var _ store.Store = (*Store)(nil)

// New opens a database connection, runs migrations, and returns a Store.
func New(dsn string) (*Store, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}

	if err := db.AutoMigrate(&account{}, &setupKey{}, &peer{}, &rule{}); err != nil {
		return nil, fmt.Errorf("auto-migrate: %w", err)
	}

	return &Store{db: db}, nil
}

// Seed inserts a default account and setup key if they don't already exist.
func (s *Store) Seed(accountID, key string) error {
	a := &account{ID: accountID, Name: "Default", CreatedAt: time.Now()}
	if err := s.db.FirstOrCreate(a, account{ID: accountID}).Error; err != nil {
		return err
	}
	sk := &setupKey{
		ID:        "default-key",
		AccountID: accountID,
		Key:       key,
		Name:      "Default key",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	return s.db.FirstOrCreate(sk, setupKey{Key: key}).Error
}

func (s *Store) GetOrCreateAccount(_ context.Context, id string) (*domain.Account, error) {
	var a account
	result := s.db.FirstOrCreate(&a, account{ID: id, Name: id, CreatedAt: time.Now()})
	if result.Error != nil {
		return nil, result.Error
	}
	return &domain.Account{ID: a.ID, Name: a.Name, CreatedAt: a.CreatedAt}, nil
}

func (s *Store) GetSetupKey(_ context.Context, key string) (*domain.SetupKey, error) {
	var sk setupKey
	if err := s.db.Where("key = ?", key).First(&sk).Error; err != nil {
		return nil, fmt.Errorf("setup key not found")
	}
	if time.Now().After(sk.ExpiresAt) {
		return nil, fmt.Errorf("setup key expired")
	}
	return toDomainSetupKey(&sk), nil
}

func (s *Store) CreateSetupKey(_ context.Context, dk *domain.SetupKey) error {
	return s.db.Create(&setupKey{
		ID:        dk.ID,
		AccountID: dk.AccountID,
		Key:       dk.Key,
		Name:      dk.Name,
		Ephemeral: dk.Ephemeral,
		ExpiresAt: dk.ExpiresAt,
		CreatedAt: dk.CreatedAt,
	}).Error
}

func (s *Store) GetSetupKeysByAccount(_ context.Context, accountID string) ([]*domain.SetupKey, error) {
	var rows []setupKey
	if err := s.db.Where("account_id = ?", accountID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.SetupKey, len(rows))
	for i, r := range rows {
		out[i] = toDomainSetupKey(&r)
	}
	return out, nil
}

func (s *Store) DeleteSetupKey(_ context.Context, accountID, id string) error {
	result := s.db.Where("id = ? AND account_id = ?", id, accountID).Delete(&setupKey{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("setup key not found")
	}
	return nil
}

func (s *Store) IncrementSetupKeyUsage(_ context.Context, keyID string) error {
	return s.db.Model(&setupKey{}).Where("id = ?", keyID).
		UpdateColumn("used_count", gorm.Expr("used_count + 1")).Error
}

func (s *Store) GetPeer(_ context.Context, wgPubKey string) (*domain.Peer, error) {
	var p peer
	if err := s.db.Where("wg_pub_key = ?", wgPubKey).First(&p).Error; err != nil {
		return nil, fmt.Errorf("peer not found")
	}
	return toDomainPeer(&p), nil
}

func (s *Store) GetPeersByAccount(_ context.Context, accountID string) ([]*domain.Peer, error) {
	var rows []peer
	if err := s.db.Where("account_id = ?", accountID).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Peer, len(rows))
	for i, r := range rows {
		out[i] = toDomainPeer(&r)
	}
	return out, nil
}

func (s *Store) GetAllPeers(_ context.Context) ([]*domain.Peer, error) {
	var rows []peer
	if err := s.db.Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Peer, len(rows))
	for i, r := range rows {
		out[i] = toDomainPeer(&r)
	}
	return out, nil
}

func (s *Store) SavePeer(_ context.Context, dp *domain.Peer) error {
	return s.db.Save(&peer{
		ID:               dp.ID,
		AccountID:        dp.AccountID,
		WGPubKey:         dp.WGPubKey,
		IP:               dp.IP,
		Hostname:         dp.Hostname,
		OS:               dp.OS,
		Kernel:           dp.Kernel,
		DNSLabel:         dp.DNSLabel,
		Tags:             joinIPs(dp.Tags),
		AllowedIPs:       joinIPs(dp.AllowedIPs),
		AdvertisedRoutes: joinIPs(dp.AdvertisedRoutes),
		Connected:        dp.Connected,
		LastSeen:         dp.LastSeen,
		CreatedAt:        dp.CreatedAt,
	}).Error
}

func (s *Store) DeletePeer(_ context.Context, wgPubKey string) error {
	return s.db.Where("wg_pub_key = ?", wgPubKey).Delete(&peer{}).Error
}

func (s *Store) GetRulesByAccount(_ context.Context, accountID string) ([]*domain.Rule, error) {
	var rows []rule
	if err := s.db.Where("account_id = ?", accountID).Order("priority asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]*domain.Rule, len(rows))
	for i, r := range rows {
		out[i] = toDomainRule(&r)
	}
	return out, nil
}

func (s *Store) SaveRule(_ context.Context, dr *domain.Rule) error {
	return s.db.Save(&rule{
		ID:        dr.ID,
		AccountID: dr.AccountID,
		Name:      dr.Name,
		Src:       dr.Src,
		Dst:       dr.Dst,
		Protocol:  dr.Protocol,
		Port:      dr.Port,
		Action:    dr.Action,
		Enabled:   dr.Enabled,
		Priority:  dr.Priority,
		CreatedAt: dr.CreatedAt,
	}).Error
}

func (s *Store) DeleteRule(_ context.Context, accountID, id string) error {
	result := s.db.Where("id = ? AND account_id = ?", id, accountID).Delete(&rule{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("rule not found")
	}
	return nil
}

// helpers ————————————————————————————————————————————————————————————————————

func toDomainSetupKey(sk *setupKey) *domain.SetupKey {
	return &domain.SetupKey{
		ID:        sk.ID,
		AccountID: sk.AccountID,
		Key:       sk.Key,
		Name:      sk.Name,
		Ephemeral: sk.Ephemeral,
		UsedCount: sk.UsedCount,
		ExpiresAt: sk.ExpiresAt,
		CreatedAt: sk.CreatedAt,
	}
}

func toDomainPeer(p *peer) *domain.Peer {
	return &domain.Peer{
		ID:               p.ID,
		AccountID:        p.AccountID,
		WGPubKey:         p.WGPubKey,
		IP:               p.IP,
		Hostname:         p.Hostname,
		OS:               p.OS,
		Kernel:           p.Kernel,
		DNSLabel:         p.DNSLabel,
		Tags:             splitIPs(p.Tags),
		AllowedIPs:       splitIPs(p.AllowedIPs),
		AdvertisedRoutes: splitIPs(p.AdvertisedRoutes),
		Connected:        p.Connected,
		LastSeen:         p.LastSeen,
		CreatedAt:        p.CreatedAt,
	}
}

func toDomainRule(r *rule) *domain.Rule {
	return &domain.Rule{
		ID:        r.ID,
		AccountID: r.AccountID,
		Name:      r.Name,
		Src:       r.Src,
		Dst:       r.Dst,
		Protocol:  r.Protocol,
		Port:      r.Port,
		Action:    r.Action,
		Enabled:   r.Enabled,
		Priority:  r.Priority,
		CreatedAt: r.CreatedAt,
	}
}

func joinIPs(ips []string) string {
	out := ""
	for i, ip := range ips {
		if i > 0 {
			out += ","
		}
		out += ip
	}
	return out
}

func splitIPs(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
