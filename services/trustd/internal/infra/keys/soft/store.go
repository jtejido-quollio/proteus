package soft

import (
	"context"
	"crypto/ed25519"
	"errors"

	"proteus/internal/domain"
	"proteus/internal/usecase"
)

type Store struct {
	manager *Manager
}

func NewStore(manager *Manager) *Store {
	return &Store{manager: manager}
}

func (s *Store) Put(_ context.Context, material usecase.KeyMaterial) error {
	if s == nil || s.manager == nil {
		return errors.New("soft key manager is required")
	}
	if len(material.PrivateKey) == 0 {
		return errors.New("private key is required")
	}
	if s.manager.keys == nil {
		s.manager.keys = make(map[string]ed25519.PrivateKey)
	}
	ref := material.Ref
	key := ed25519.PrivateKey(material.PrivateKey)
	if err := validateKeyRef(ref); err != nil {
		return err
	}
	s.manager.keys[keyRefKey(ref)] = append(ed25519.PrivateKey(nil), key...)
	return nil
}

func (s *Store) Delete(_ context.Context, ref domain.KeyRef) error {
	if s == nil || s.manager == nil {
		return errors.New("soft key manager is required")
	}
	if err := validateKeyRef(ref); err != nil {
		return err
	}
	if s.manager.keys != nil {
		delete(s.manager.keys, keyRefKey(ref))
	}
	return nil
}
