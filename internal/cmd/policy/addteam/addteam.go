// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package addteam

import (
	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/policy/persistent"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv02 "github.com/gittuf/gittuf/internal/tuf/v02"
	"github.com/spf13/cobra"
)

type options struct {
	p            *persistent.Options
	policyName   string
	teamID       string
	principalIDs []string
	threshold    int
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.policyName,
		"policy-name",
		policy.TargetsRoleName,
		"name of policy file to add team to",
	)

	cmd.Flags().StringVar(
		&o.teamID,
		"team-ID",
		"",
		"team ID",
	)
	cmd.MarkFlagRequired("team-ID") //nolint:errcheck

	cmd.Flags().StringArrayVar(
		&o.principalIDs,
		"principalIDs",
		[]string{},
		"authorized principalIDs of this team",
	)

	cmd.Flags().IntVar(
		&o.threshold,
		"threshold",
		1,
		"threshold of required valid signatures",
	)
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	opts := []trustpolicyopts.Option{}
	if o.p.WithRSLEntry {
		opts = append(opts, trustpolicyopts.WithRSLEntry())
	}

	principals, err := repo.ListPrincipals(cmd.Context(), policy.PolicyStagingRef, o.policyName)
	if err != nil {
		return err
	}

	members := []tuf.Principal{}
	for _, principalID := range o.principalIDs {
		principal, exists := principals[principalID]
		if !exists {
			return tuf.ErrInvalidPrincipalID
		}
		members = append(members, principal)
	}

	team, err := tufv02.NewTeam(o.teamID, members, o.threshold)
	if err != nil {
		return err
	}

	return repo.AddPrincipalToTargets(cmd.Context(), signer, o.policyName, []tuf.Principal{team}, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "add-team",
		Short:             "Add a trusted team to a policy file",
		Long:              `The 'add-team' command adds a trusted team to a gittuf policy file. In gittuf, a team definition consists of a unique identifier ('--team-ID'), zero or more unique IDs for authorized team members ('--principal-IDs'), and a threshold. By default, the main policy file (targets) is used, which can be overridden with the '--policy-name' flag.`,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
