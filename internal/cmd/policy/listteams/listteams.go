package listteams

import (
	"fmt"
	"strings"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/spf13/cobra"
)

const indentString = "    "

type options struct {
	policyRef  string
	policyName string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&o.policyRef,
		"policy-ref",
		"policy",
		"specify which policy ref should be inspected",
	)

	cmd.Flags().StringVar(
		&o.policyName,
		"policy-name",
		tuf.TargetsRoleName,
		"specify rule file to list teams for",
	)
}

func (o *options) Run(cmd *cobra.Command, _ []string) error {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return err
	}

	teams, err := repo.ListTeams(cmd.Context(), o.policyRef, o.policyName)
	if err != nil {
		return err
	}

	for _, team := range teams {
		fmt.Printf("Team %s (threshold %d):\n", team.ID(), team.GetThreshold())

		if members := team.GetMembers(); len(members) > 0 {
			fmt.Printf("%sMembers:\n", indentString)
			for _, member := range members {
				fmt.Printf("%s%s\n", strings.Repeat(indentString, 2), member.ID())
				for _, key := range member.Keys() {
					fmt.Printf("%s%s (%s)\n", strings.Repeat(indentString, 3), key.KeyID, key.KeyType)
				}
			}
		}
	}

	return nil
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:               "list-teams",
		Short:             "List teams for the current policy in the specified rule file",
		Long:              `The 'list-teams' command lists all trusted teams defined in a gittuf policy rule file. By default, the main policy file (targets) is used, which can be overridden with the '--policy-name' flag.`,
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
