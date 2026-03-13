package cook

const (
	EmptyString = ""

	DefaultLastKeep = 2

	DirPermOwnerGroup = 0750

	CurrentLink = "current"
	TempLink    = "tmp_"
	TempDir     = ".tmp"

	DeployDirName = "deploy"

	// git clone opts
	GitDefaultDepth      = 1
	DefaultCommitHashLen = 8
	GitDirectory         = ".git"

	AuthTypeBasic    = "basic"
	AuthTypeSSHKey   = "ssh-key"
	AuthTypeSSHAgent = "ssh-aget"
	GitConst         = "git "
)
