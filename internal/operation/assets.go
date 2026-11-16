package operation

import (
	_ "embed"
)

var (
	//go:embed asset/favicon.ico
	Favicon []byte

	// LoginPage is the HTML shell for the route-local protect login form.
	// Templates are executed with html/template by the auth middleware.
	//go:embed asset/login.html
	LoginPage []byte
)
