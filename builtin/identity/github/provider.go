package gihub

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type githubIdentityProvider struct {
	*framework.IdentityProvider
}

func GithubIdentityProviderFactory(config *logical.IdentityProviderConfig) (logical.IdentityProvider, error) {
	return newGithubIdentityProvider(config), nil
}

func newGithubIdentityProvider(config *logical.IdentityProviderConfig) *githubIdentityProvider {
	var p githubIdentityProvider
	p.IdentityProvider = &framework.IdentityProvider{
		Type: framework.GithubIdentityProvider,
	}
	return &p
}
