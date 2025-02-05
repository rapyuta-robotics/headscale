package hscontrol

import (
	"errors"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"strings"
)

var (
	ErrPolicyNotFound                = errors.New("acl policy not found")
	ErrPolicyUpdateIsDisabled        = errors.New("update is disabled for modes other than 'database'")
	ErrPolicyUpdatedInAnotherSession = errors.New("updated in another session")
)

// Policy represents a policy in the database.
type Policy struct {
	gorm.Model
	Version uint `gorm:"unique"`
	// Data contains the policy in HuJSON format.
	Data string
}

func (h *Headscale) SetACLPolicy(version uint, policy string) (*Policy, error) {
	var dbPolicy Policy
	p := Policy{
		Data: policy,
	}

	err := h.db.Transaction(func(tx *gorm.DB) error {
		err := tx.Exec(`set transaction isolation level serializable`).Error
		if err != nil {
			return err
		}

		if err := tx.
			Order("version DESC").
			Limit(1).
			First(&dbPolicy).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// Create a new policy in case of bootstrap
				p.Version = 1
				if err := h.db.Clauses(clause.Returning{}).Create(&p).Error; err != nil {
					return err
				}
				return nil
			}
			return err
		}

		if version != dbPolicy.Version {
			return ErrPolicyUpdatedInAnotherSession
		}

		p.Version = dbPolicy.Version + 1
		if err := tx.Clauses(clause.Returning{}).Create(&p).Error; err != nil {
			if strings.Contains(err.Error(), "could not serialize access due to read/write dependencies") {
				return ErrPolicyUpdatedInAnotherSession
			}
			if strings.Contains(err.Error(), "duplicate key value violates") {
				return ErrPolicyUpdatedInAnotherSession
			}
			return err
		}
		return nil
	})

	return &p, err
}

func (h *Headscale) GetACLPolicy() (*Policy, error) {
	var p Policy

	// Query:
	// SELECT * FROM policies ORDER BY version DESC LIMIT 1;
	if err := h.db.
		Order("version DESC").
		Limit(1).
		First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPolicyNotFound
		}

		return nil, err
	}
	return &p, nil
}
