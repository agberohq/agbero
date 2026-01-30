package woos

import (
	"github.com/olekukonko/errors"
	"github.com/olekukonko/errors/errmgr"
)

var (
	ErrDefined = errmgr.Define("ErrDefined,", "error occurred with (%s): %s")
)

var (
	ErrAlreadyExists = errors.New("reference required")
)

// server
var (
	ErrHostManagerRequired  = errors.New("host manager is required")
	ErrGlobalConfigRequired = errors.New("global config is required")
	ErrPortConflict         = errors.New("port conflict")
	ErrNoBindAddr           = errors.New("no http/https/tcp bind addresses configured")
	ErrLoggerRequired       = errors.New("logger is required")
)
