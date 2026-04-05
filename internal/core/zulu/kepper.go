package zulu

//import (
//	"github.com/agberohq/agbero/internal/pkg/keepercfg"
//	"github.com/agberohq/keeper"
//	"github.com/olekukonko/ll"
//)
//
//// NewKeeperFor opens keeper using central config — reusable pattern.
//func OpenKeeper(logger *ll.Logger, dbPath string, passphrase []byte) (*keeper.Keeper, error) {
//	cfg := &keepercfg.KeeperConfig{
//		DBPath:     dbPath,
//		Passphrase: passphrase,
//		Logger:     logger,
//	}
//	return keepercfg.KeeperOpen(cfg)
//}
//
//// NewKeeperFor creates a NEW keeper — for first-time setup.
//func NewKeeperFor(logger *ll.Logger, dbPath string, passphrase []byte) (*keeper.Keeper, error) {
//	cfg := &keepercfg.KeeperConfig{
//		DBPath:     dbPath,
//		Passphrase: passphrase,
//		Logger:     logger,
//	}
//	return keepercfg.KeeperNew(cfg)
//}
