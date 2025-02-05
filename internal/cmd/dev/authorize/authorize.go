// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package authorize

import (
	"github.com/gittuf/gittuf/internal/cmd/attest/authorize"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := authorize.New()
	cmd.Deprecated = "switch to \"gittuf attest authorize\""
	return cmd
}
