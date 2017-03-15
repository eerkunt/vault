package ldap

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type ldapIdentityProvider struct {
	*framework.IdentityProvider
}

func LdapIdentityProviderFactory(config *logical.IdentityProviderConfig) (logical.IdentityProvider, error) {
	return newLdapIdentityProvider(config), nil
}

func newLdapIdentityProvider(config *logical.IdentityProviderConfig) *ldapIdentityProvider {
	var p ldapIdentityProvider
	p.IdentityProvider = &framework.IdentityProvider{
		Type: framework.LdapIdentityProvider,
	}
	return &p
}
