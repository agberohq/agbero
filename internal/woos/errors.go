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
