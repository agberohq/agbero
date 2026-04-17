package alaye

import "time"

type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	Role         string    `json:"role"`
	Notes        string    `json:"notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
