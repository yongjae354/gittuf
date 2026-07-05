// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package v02

// This package defines gittuf's take on TUF metadata. There are some minor
// changes, such as the addition of `custom` to delegation entries. Some of it,
// however, is inspired by or cloned from the go-tuf implementation.

import (
	"fmt"

	"github.com/gittuf/gittuf/internal/common/set"
	"github.com/gittuf/gittuf/internal/tuf"
	v01 "github.com/gittuf/gittuf/internal/tuf/v01"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
)

const (
	associatedIdentityKey = "(associated identity)"
)

// Key defines the structure for how public keys are stored in TUF metadata. It
// implements the tuf.Principal and is used for backwards compatibility where a
// Principal is always represented directly by a signing key or identity.
type Key = v01.Key

// NewKeyFromSSLibKey converts the signerverifier.SSLibKey into a Key object.
func NewKeyFromSSLibKey(key *signerverifier.SSLibKey) *Key {
	k := Key(*key)
	return &k
}

type Person struct {
	PersonID             string            `json:"personID"`
	PublicKeys           map[string]*Key   `json:"keys"`
	AssociatedIdentities map[string]string `json:"associatedIdentities"`
	Custom               map[string]string `json:"custom"`
}

func (p *Person) ID() string {
	return p.PersonID
}

func (p *Person) Keys() []*signerverifier.SSLibKey {
	keys := make([]*signerverifier.SSLibKey, 0, len(p.PublicKeys))
	for _, key := range p.PublicKeys {
		key := signerverifier.SSLibKey(*key)
		keys = append(keys, &key)
	}

	return keys
}

func (p *Person) CustomMetadata() map[string]string {
	var metadata map[string]string

	for provider, identity := range p.AssociatedIdentities {
		if metadata == nil {
			metadata = map[string]string{}
		}
		metadata[fmt.Sprintf("%s %s", associatedIdentityKey, provider)] = identity
	}

	for key, value := range p.Custom {
		if metadata == nil {
			metadata = map[string]string{}
		}
		metadata[key] = value
	}

	return metadata
}

// Team defines the structure for how a team identity is stored in policy
// metadata. It implements tuf.Principal.
type Team struct {
	// TeamID is a unique name or identifier for a team.
	TeamID string `json:"teamID"`
	// Metadata stores custom metadata for a team.
	Metadata map[string]string `json:"custom"`
	// Members stores references to individual persons of a team.
	Members []*Person `json:"members"`
	// Threshold defines the minimum number required for a team to reach
	// agreement.
	Threshold int `json:"threshold"`
}

// NewTeam constructs a Team from existing person principals. Support for keys and nested teams are deferred.
func NewTeam(teamID string, principals []tuf.Principal, threshold int) (*Team, error) {
	team := &Team{
		TeamID:    teamID,
		Threshold: threshold,
	}
	for _, principal := range principals {
		switch p := principal.(type) {
		case *Person:
			team.Members = append(team.Members, p)
		default:
			return nil, tuf.ErrInvalidPrincipalType
		}
	}
	return team, nil
}

// ID returns the team ID of a team.
func (t *Team) ID() string {
	return t.TeamID
}

// Keys returns all keys of a team.
func (t *Team) Keys() []*signerverifier.SSLibKey {
	keys := []*signerverifier.SSLibKey{}
	for _, member := range t.Members {
		keys = append(keys, member.Keys()...)
	}

	return keys
}

// CustomMetadata returns the custom metadata of a team.
func (t *Team) CustomMetadata() map[string]string {
	return t.Metadata
}

// GetMembers returns the persons that are members of a team.
func (t *Team) GetMembers() []*Person {
	return t.Members
}

// GetThreshold returns the team's internal threshold.
func (t *Team) GetThreshold() int {
	return t.Threshold
}

// Role records common characteristics recorded in a role entry in Root metadata
// and in a delegation entry.
type Role struct {
	PrincipalIDs *set.Set[string] `json:"principalIDs"`
	Threshold    int              `json:"threshold"`
}
