package vault

import (
	"github.com/fatih/structs"
	memdb "github.com/hashicorp/go-memdb"
	"github.com/hashicorp/vault/helper/salt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	// Paths of identity store
	pathIdentityRegister = "identity/register?$"
	pathEntityPrefix     = "entity/" // + framework.GenericNameRegex("entity_name")
	pathEntityList       = "entity/?"
	pathGroupPrefix      = "group/" // + framework.GenericNameRegex("group_name")
	pathGroupList        = "group/?"

	// Storage paths in identity store
	entityPrefix = "entity/"
)

type identityStore struct {
	view logical.Storage
	salt *salt.Salt
	*framework.Backend
	groupDBSchema  *memdb.DBSchema
	groupDB        *memdb.MemDB
	entityDBSchema *memdb.DBSchema
	entityDB       *memdb.MemDB
	Providers      []*logical.IdentityProvider
}

func IdentityStoreFactory(config *logical.BackendConfig) (logical.Backend, error) {
	identityBackend := NewIdentityStore(config)
	logicalIdentityBE, err := identityBackend.Setup(config)
	if err != nil {
		return nil, err
	}
	return logicalIdentityBE, nil
}

type entityStorageEntry struct {
	Name         string                       `json:"name" structs:"name" mapstructure:"name"`
	ID           string                       `json:"id" structs:"id" mapstructure:"id"`
	Aliases      []string                     `json:"aliases" structs:"aliases" mapstructure:"aliases"`
	Identities   []*identityStorageEntry      `json:"identities" structs:"identities" mapstructure:"identities"`
	Groups       []*identityGroupStorageEntry `json:"groups" structs:"groups" mapstructure:"groups"`
	Metadata     map[string]interface{}       `json:"metadata" structs:"metadata" mapstructure:"metadata"`
	Implicit     bool                         `json:"implicit" structs:"implicit" mapstructure:"implicit"`
	SaltedTokens []string                     `json:"salted_tokens" structs:"salted_tokens" mapstructure:"salted_tokens"`
}

type identityStorageEntry struct {
	Type string      `json:"type" structs:"type" mapstructure:"type"`
	Data interface{} `json:"data" structs:"data" mapstructure:"data"`
}

type identityGroupStorageEntry struct {
	Filters  []IdentityFilter            `json:"filters" structs:"filters" mapstructure:"filters"`
	Name     string                      `json:"name" structs:"name" mapstructure:"name"`
	ID       string                      `json:"id" structs:"id" mapstructure:"id"`
	Groups   []identityGroupStorageEntry `json:"groups" structs:"groups" mapstructure:"groups"`
	Policies []string                    `json:"policies" structs:"policies" mapstructure:"policies"`
}

type IdentityFilter struct {
	Type string      `json:"type" structs:"type" mapstructure:"type"`
	Data interface{} `json:"data" structs:"data" mapstructure:"data"`
}

func NewIdentityStore(config *logical.BackendConfig) *identityStore {
	iStore := &identityStore{
		view: config.StorageView,
	}

	salt, err := salt.NewSalt(iStore.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
	})
	if err != nil {
		return nil
	}

	iStore.salt = salt

	iStore.Backend = &framework.Backend{
		Paths: []*framework.Path{
			{
				Pattern: pathIdentityRegister,

				Fields: map[string]*framework.FieldSchema{
					"type": &framework.FieldSchema{
						Type: framework.TypeString,
					},
					"data": &framework.FieldSchema{
						Type: framework.TypeMap,
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: iStore.identityRegisterCreateUpdate,
					logical.UpdateOperation: iStore.identityRegisterCreateUpdate,
				},
			},
			{
				Pattern: pathEntityPrefix + framework.GenericNameRegex("entity_name"),

				Fields: map[string]*framework.FieldSchema{
					"entity_name": &framework.FieldSchema{
						Type: framework.TypeString,
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation:   iStore.entityRead,
					logical.DeleteOperation: iStore.entityDelete,
				},
			},
			{
				Pattern: pathEntityList,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ListOperation: iStore.entityList,
				},
			},
			{
				Pattern: pathGroupPrefix + framework.GenericNameRegex("group_name"),
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: iStore.groupCreateUpdate,
					logical.UpdateOperation: iStore.groupCreateUpdate,
					logical.ReadOperation:   iStore.groupRead,
					logical.DeleteOperation: iStore.groupDelete,
				},
			},
			{
				Pattern: pathGroupList,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ListOperation: iStore.entityList,
				},
			},
		},
	}

	return iStore
}

func (i *identityStore) setEntityEntry(s logical.Storage, entityName string, entity *entityStorageEntry) error {
	entryIndex := entityPrefix + i.salt.SaltID(entityName)

	entry, err := logical.StorageEntryJSON(entryIndex, entity)
	if err != nil {
		return err
	}

	if err = s.Put(entry); err != nil {
		return err
	}

	return nil
}

func (i *identityStore) entityEntry(s logical.Storage, entityName string) (*entityStorageEntry, error) {
	var entity entityStorageEntry
	if entry, err := s.Get(entityPrefix + i.salt.SaltID(entityName)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&entity); err != nil {
		return nil, err
	}

	return &entity, nil
}

func (i *identityStore) deleteEntityEntry(s logical.Storage, entityName string) error {
	entryIndex := entityPrefix + i.salt.SaltID(entityName)
	return s.Delete(entryIndex)
}

func (i *identityStore) identityRegisterCreateUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	identity := &identityStorageEntry{
		Type: d.Get("type").(string),
		Data: d.Get("data"),
	}

	entity := &entityStorageEntry{
		Name:       "entityName",
		ID:         "entityID",
		Identities: []*identityStorageEntry{identity},
	}

	err := i.setEntityEntry(req.Storage, entity.Name, entity)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"entity_name": entity.Name,
			"entity_id":   entity.ID,
		},
	}

	return resp, nil
}

func (i *identityStore) entityRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entity, err := i.entityEntry(req.Storage, d.Get("entity_name").(string))
	if err != nil {
		return nil, err
	}
	if entity == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: structs.New(entity).Map(),
	}

	return resp, nil
}

func (i *identityStore) entityDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, i.deleteEntityEntry(req.Storage, d.Get("entity_name").(string))
}

func (i *identityStore) entityList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (i *identityStore) groupCreateUpdate(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (i *identityStore) groupRead(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (i *identityStore) groupDelete(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

func (i *identityStore) groupList(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}
