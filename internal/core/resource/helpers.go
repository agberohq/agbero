package resource

import (
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/jack"
)

type Patience struct {
	Route *alaye.Route
	doc   *jack.Doctor
}
