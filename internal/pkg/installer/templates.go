package installer

import _ "embed"

//go:embed data/banner.txt
var BannerTmpl string

//go:embed data/agbero.hcl
var ConfigTmpl string

//go:embed data/web.hcl
var TplWebHcl []byte

//go:embed data/admin.hcl
var TplAdminHcl []byte
