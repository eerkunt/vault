package logical

type IdentityProvider interface {
	Validate(*Request) (*Response, error)
}

type IdentityProviderConfig struct{}

type IdentityProviderFactory func(*IdentityProviderConfig) (IdentityProvider, error)
