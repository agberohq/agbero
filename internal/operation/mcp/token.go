package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/keeper"
)

const (
	TokenIssuer   = "agbero"
	TokenAudience = "agbero-mcp"

	ScopeRead = "mcp:read"
	ScopePlan = "mcp:plan"

	DefaultTokenTTL = 8 * time.Hour
	MaxTokenTTL     = 24 * time.Hour
)

var (
	ErrKeeperLocked = errors.New("mcp: keeper is locked")
	ErrInvalidScope = errors.New("mcp: invalid or missing scope")
	ErrInvalidToken = errors.New("mcp: invalid token")
)

var (
	tokenKeyPath     = expect.Vault().Key("mcp/token/signing-key")
	tokenPrevKeyPath = expect.Vault().Key("mcp/token/signing-key/previous")
)

// Keeper is the subset of the keeper store the token layer needs. The daemon
// passes its *keeper.Keeper; tests use a map-backed fake.
type Keeper interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	IsLocked() bool
}

// Claims is the MCP token payload. Scope is a space-separated list of
// mcp:read / mcp:plan; mcp:apply does not exist.
type Claims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// TokenStore mints and verifies HMAC tokens. The signing key lives in the
// keeper (vault://key/mcp/token/signing-key), never in a file.
type TokenStore struct {
	keeper Keeper

	mu       sync.Mutex
	current  []byte
	previous []byte
}

func NewTokenStore(k Keeper) *TokenStore {
	return &TokenStore{keeper: k}
}

// Ensure creates the signing key when it is missing. Requires an unlocked
// keeper.
func (s *TokenStore) Ensure() error {
	if s.keeper == nil {
		return errors.New("mcp: keeper is not configured")
	}
	if s.keeper.IsLocked() {
		return ErrKeeperLocked
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.keeper.Get(tokenKeyPath); err == nil {
		return nil
	} else if !isNotFound(err) {
		return err
	}
	key, err := randomKey()
	if err != nil {
		return err
	}
	return s.keeper.Set(tokenKeyPath, key)
}

// Rotate moves the current key to previous and creates a new current key.
// Tokens signed with the previous key remain valid until they expire or the
// next rotation; callers should retire the previous key after MaxTokenTTL.
func (s *TokenStore) Rotate() error {
	if s.keeper == nil {
		return errors.New("mcp: keeper is not configured")
	}
	if s.keeper.IsLocked() {
		return ErrKeeperLocked
	}
	cur, err := s.keeper.Get(tokenKeyPath)
	if err != nil {
		return err
	}
	if err := s.keeper.Set(tokenPrevKeyPath, cur); err != nil {
		return err
	}
	next, err := randomKey()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.current, s.previous = nil, nil
	s.mu.Unlock()
	return s.keeper.Set(tokenKeyPath, next)
}

// Mint returns a signed token and its claims.
func (s *TokenStore) Mint(sub string, scopes []string, ttl time.Duration) (string, *Claims, error) {
	if s.keeper == nil {
		return "", nil, errors.New("mcp: keeper is not configured")
	}
	if s.keeper.IsLocked() {
		return "", nil, ErrKeeperLocked
	}
	if err := s.Ensure(); err != nil {
		return "", nil, err
	}
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return "", nil, errors.New("mcp: subject is required")
	}
	scope, err := normalizeScopes(scopes)
	if err != nil {
		return "", nil, err
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	if ttl > MaxTokenTTL {
		return "", nil, errors.New("mcp: token TTL exceeds 24h")
	}
	key, kid, err := s.signingKey()
	if err != nil {
		return "", nil, err
	}

	now := time.Now().UTC()
	jti, err := randomID()
	if err != nil {
		return "", nil, err
	}
	claims := &Claims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    TokenIssuer,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{TokenAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		return "", nil, err
	}
	return signed, claims, nil
}

// Verify validates signature, issuer, audience, subject, and expiry. The
// caller still checks the JTI revocation list and the config/token scope
// intersection.
func (s *TokenStore) Verify(raw string) (*Claims, error) {
	if s.keeper == nil {
		return nil, errors.New("mcp: keeper is not configured")
	}
	if s.keeper.IsLocked() {
		return nil, ErrKeeperLocked
	}
	keys, err := s.keys()
	if err != nil {
		return nil, err
	}

	claims := new(Claims)
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, ErrInvalidToken
		}
		kid, _ := t.Header["kid"].(string)
		key := keys[kid]
		if len(key) == 0 {
			return nil, ErrInvalidToken
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || tok == nil || !tok.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Issuer != TokenIssuer || claims.Subject == "" || claims.ID == "" {
		return nil, ErrInvalidToken
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != TokenAudience {
		return nil, ErrInvalidToken
	}
	if claims.ExpiresAt == nil || time.Now().After(claims.ExpiresAt.Time) {
		return nil, ErrInvalidToken
	}
	if err := validateScopes(claims.Scope); err != nil {
		return nil, err
	}
	return claims, nil
}

func (s *TokenStore) signingKey() ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, "", err
	}
	if len(s.current) == 0 {
		return nil, "", ErrInvalidToken
	}
	return s.current, kidForKey(s.current), nil
}

func (s *TokenStore) keys() (map[string][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return nil, err
	}
	keys := make(map[string][]byte, 2)
	if len(s.current) > 0 {
		keys[kidForKey(s.current)] = s.current
	}
	if len(s.previous) > 0 {
		keys[kidForKey(s.previous)] = s.previous
	}
	return keys, nil
}

func (s *TokenStore) loadLocked() error {
	if len(s.current) > 0 {
		return nil
	}
	cur, err := s.keeper.Get(tokenKeyPath)
	if err != nil {
		return err
	}
	s.current = cur
	prev, err := s.keeper.Get(tokenPrevKeyPath)
	if err == nil {
		s.previous = prev
	} else if !isNotFound(err) {
		return err
	}
	return nil
}

func normalizeScopes(scopes []string) (string, error) {
	set := make(map[string]struct{}, len(scopes)+1)
	for _, raw := range scopes {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			continue
		}
		switch scope {
		case ScopeRead, ScopePlan:
			set[scope] = struct{}{}
		case "mcp:apply", "mcp:admin":
			return "", errors.New("mcp: apply/admin scopes do not exist")
		default:
			return "", ErrInvalidScope
		}
	}
	if _, ok := set[ScopePlan]; ok {
		set[ScopeRead] = struct{}{}
	}
	if _, ok := set[ScopeRead]; !ok {
		return "", ErrInvalidScope
	}
	parts := make([]string, 0, 2)
	parts = append(parts, ScopeRead)
	if _, ok := set[ScopePlan]; ok {
		parts = append(parts, ScopePlan)
	}
	return strings.Join(parts, " "), nil
}

func validateScopes(scope string) error {
	parts := strings.Fields(scope)
	if len(parts) == 0 {
		return ErrInvalidScope
	}
	seenRead := false
	for _, p := range parts {
		switch p {
		case ScopeRead:
			seenRead = true
		case ScopePlan:
			// plan implies read; accept either order.
		default:
			return ErrInvalidScope
		}
	}
	if !seenRead {
		return ErrInvalidScope
	}
	if strings.Contains(scope, ScopePlan) && !strings.Contains(scope, ScopeRead) {
		return ErrInvalidScope
	}
	return nil
}

func HasScope(c *Claims, scope string) bool {
	if c == nil {
		return false
	}
	for _, s := range strings.Fields(c.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}

func kidForKey(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

func randomKey() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isNotFound(err error) bool {
	return errors.Is(err, keeper.ErrKeyNotFound)
}
