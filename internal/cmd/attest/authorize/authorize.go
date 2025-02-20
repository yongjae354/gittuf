// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package authorize

import (
	"fmt"

	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/cmd/attest/persistent"
	"github.com/spf13/cobra"
)

type options struct {
	p       *persistent.Options
	fromRef string
	revoke  bool
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&o.fromRef,
		"from-ref",
		"f",
		"",
		"ref to authorize merging changes from",
	)
	cmd.MarkFlagRequired("from-ref") //nolint:errcheck

	cmd.Flags().BoolVarP(
		&o.revoke,
		"revoke",
		"r",
		false,
		"revoke existing authorization",
	)
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	repo, err := gittuf.LoadRepository()
	if err != nil {
		return err
	}

	signer, err := gittuf.LoadSigner(repo, o.p.SigningKey)
	if err != nil {
		return err
	}

	if o.revoke {
		if len(args) < 3 {
			return fmt.Errorf("insufficient parameters for revoking authorization, requires <targetRef> <fromID> <targetTreeID>")
		}

		return repo.RemoveReferenceAuthorization(cmd.Context(), signer, args[0], args[1], args[2], true)
	}

	return repo.AddReferenceAuthorization(cmd.Context(), signer, args[0], o.fromRef, true)
}

func New(persistent *persistent.Options) *cobra.Command {
	o := &options{p: persistent}
	cmd := &cobra.Command{
		Use:               "authorize",
		Short:             "Add or revoke reference authorization",
		Args:              cobra.MinimumNArgs(1),
		RunE:              o.Run,
		DisableAutoGenTag: true,
	}
	o.AddFlags(cmd)

	return cmd
}
