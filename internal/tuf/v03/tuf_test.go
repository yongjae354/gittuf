// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package v03

import (
	"encoding/json"
	"testing"

	"github.com/gittuf/gittuf/internal/signerverifier/ssh"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/stretchr/testify/assert"
)

func TestTeam(t *testing.T) {
	keyR := ssh.NewKeyFromBytes(t, rootPubKeyBytes)
	key := NewKeyFromSSLibKey(keyR)

	person := &Person{
		PersonID: "jane.doe",
		PublicKeys: map[string]*Key{
			key.KeyID: key,
		},
	}

	team, err := NewTeam("team1", []tuf.Principal{person}, 2)
	assert.Nil(t, err)
	team.Metadata = map[string]string{"some_key": "some_value"}

	var _ tuf.Principal = team

	assert.Equal(t, "team1", team.ID())
	assert.Equal(t, 2, team.GetThreshold())
	assert.Equal(t, map[string]string{"some_key": "some_value"}, team.CustomMetadata())

	assert.Len(t, team.Keys(), 1)
	assert.Equal(t, key.KeyID, team.Keys()[0].KeyID)

	assert.Equal(t, []*Person{person}, team.GetMembers())

	_, err = NewTeam("invalid-team", []tuf.Principal{key}, 1)
	assert.ErrorIs(t, err, tuf.ErrInvalidPrincipalType)
}

func TestDelegationsUnmarshalTeam(t *testing.T) {
	keyR := ssh.NewKeyFromBytes(t, rootPubKeyBytes)
	key := NewKeyFromSSLibKey(keyR)
	person := &Person{
		PersonID: "jane.doe",
		PublicKeys: map[string]*Key{
			key.KeyID: key,
		},
	}

	delegations := &Delegations{
		Principals: map[string]tuf.Principal{
			"team1": &Team{
				TeamID:    "team1",
				Members:   []*Person{person},
				Threshold: 1,
			},
		},
		Roles: []*Delegation{AllowRule()},
	}

	bytes, err := json.Marshal(delegations)
	assert.Nil(t, err)

	roundTripped := &Delegations{}
	err = json.Unmarshal(bytes, roundTripped)
	assert.Nil(t, err)

	principal, ok := roundTripped.Principals["team1"]
	assert.True(t, ok)

	team, ok := principal.(*Team)
	assert.True(t, ok, "team must round-trip back into a *Team principal")
	assert.Equal(t, "team1", team.ID())
	assert.Equal(t, 1, team.GetThreshold())
	assert.Len(t, team.Keys(), 1)
}
