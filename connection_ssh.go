package fpoc

import (
	"context"
	"crypto"

	"gitlab.com/gitlab-org/fleeting/fleeting/provider"
)

type PrivPub interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
}

// ssh handles non static ssh keys
func (g *InstanceGroup) ssh(ctx context.Context, info provider.ConnectInfo) error {
	privateKeyPem, _, err := GetInstanceSSHKey(g.settings, info.ID, g.SSHStoragePath)
	if err != nil {
		return err
	}
	info.Key = privateKeyPem
	return nil
}
