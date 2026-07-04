package updateteam

import (
	"github.com/gittuf/gittuf/experimental/gittuf"
	trustpolicyopts "github.com/gittuf/gittuf/experimental/gittuf/options/trustpolicy"
	"github.com/gittuf/gittuf/internal/cmd/policy/persistent"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/internal/tuf"
	tufv03 "github.com/gittuf/gittuf/internal/tuf/v03"
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
		"name of policy file to update team in",
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
	cmd.MarkFlagRequired("principalIDs")

	cmd.Flags().IntVar(
		&o.threshold,
		"threshold",
		1,
		"threshold of required valid signatures",
	)
	cmd.MarkFlagRequired("threshold")
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

	team, err := tufv03.NewTeam(o.teamID, members, o.threshold)
	if err != nil {
		return err
	}

	return repo.UpdatePrincipalInTargets(cmd.Context(), signer, o.policyName, team, true, opts...)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "update-team",
		Short:             "Update an existing trusted team in a policy file",
		Long:              `The 'update-team' command updates the principals or the theshold of an existing trusted team in a gittuf policy file. In gittuf, a team definition consists of a unique identifier ('--team-ID'), zero or more unique IDs for authorized team members ('--principal-IDs'), and a threshold. By default, the main policy file (targets) is used, which can be overridden with the '--policy-name' flag.`,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
