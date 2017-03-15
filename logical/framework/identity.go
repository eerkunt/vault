package framework

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
)

const (
	LdapIdentityProvider   = "ldap-identity-provider"
	GithubIdentityProvider = "github-identity-provider"
)

type IdentityProvider struct {
	Type string
}

func (p *IdentityProvider) Validate(*logical.Request) (*logical.Response, error) {
	fmt.Printf("in framework identityprovider validate()\n")
	return nil, nil
}
