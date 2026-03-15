package main

import _ "embed"

//go:embed template/proxy.hcl
var proxyTpl string

//go:embed template/static.hcl
var staticTpl string

//go:embed template/tcp.hcl
var tcpTpl string
