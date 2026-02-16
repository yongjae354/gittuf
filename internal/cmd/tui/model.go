// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/gittuf/gittuf/experimental/gittuf"
	"github.com/gittuf/gittuf/internal/tuf"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

type screen int

const (
	screenChoice screen = iota // initial screen
	screenPolicy
	screenTrust
	screenAddRule
	screenRemoveRule
	screenListRules
	screenReorderRules
	screenListGlobalRules
	screenAddGlobalRule
	screenUpdateGlobalRule
	screenRemoveGlobalRule
)

type item struct {
	title, desc string
}

// Note: virtual methods must be implemented for the item struct
// Title returns the title of the item.
func (i item) Title() string { return i.title }

// Description returns the description of the item.
func (i item) Description() string { return i.desc }

// FilterValue returns the value to filter on.
func (i item) FilterValue() string { return i.title }

type model struct {
	screen           screen
	choiceList       list.Model
	policyScreenList list.Model
	trustScreenList  list.Model
	rules            []rule
	ruleList         list.Model
	globalRules      []globalRule
	globalRuleList   list.Model
	inputs           []textinput.Model
	focusIndex       int
	cursorMode       cursor.Mode
	repo             *gittuf.Repository
	signer           dsse.SignerVerifier
	policyName       string
	options          *options
	footer           string
	readOnly         bool
}

// inputField describes a single text input's placeholder and prompt label.
type inputField struct {
	placeholder string
	prompt      string
}

// newDelegate creates a styled list delegate for use in all list.Model instances.
func newDelegate() list.DefaultDelegate {
	d := list.NewDefaultDelegate()
	d.Styles.SelectedTitle = selectedItemStyle
	d.Styles.SelectedDesc = selectedItemStyle
	d.Styles.NormalTitle = itemStyle
	d.Styles.NormalDesc = itemStyle
	return d
}

// newMenuList creates a configured list.Model with default settings.
func newMenuList(title string, items []list.Item, delegate list.DefaultDelegate) list.Model {
	l := list.New(items, delegate, 0, 0)
	l.Title = title
	l.Styles.Title = titleStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	return l
}

// initInputs creates a slice of text inputs from field definitions.
// The first field is focused; the rest are blurred.
func initInputs(fields []inputField) []textinput.Model {
	inputs := make([]textinput.Model, len(fields))
	for i, f := range fields {
		t := textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 64
		t.Placeholder = f.placeholder
		t.Prompt = f.prompt
		if i == 0 {
			t.Focus()
			t.PromptStyle = focusedStyle
			t.TextStyle = focusedStyle
		} else {
			t.Blur()
			t.PromptStyle = blurredStyle
			t.TextStyle = blurredStyle
		}
		inputs[i] = t
	}
	return inputs
}

// initialModel returns the initial model for the Terminal UI.
func initialModel(o *options) (model, error) {
	repo, err := gittuf.LoadRepository(".")
	if err != nil {
		return model{}, err
	}

	// Determine if we are in read-only mode. (read-only mode specified, or no signing key found)
	readOnly := o.readOnly
	var signer dsse.SignerVerifier
	var footer string

	if !readOnly {
		signer, err = gittuf.LoadSigner(repo, o.p.SigningKey)
		if err != nil {
			if !errors.Is(err, gittuf.ErrSigningKeyNotSpecified) {
				return model{}, fmt.Errorf("failed to load signing key from Git config: %w", err)
			}
			readOnly = true
			footer = "No signing key found in Git config, running in read-only mode."
		}
	}

	delegate := newDelegate()

	// Policy screen items - read-only mode only shows List Rules
	var policyItems []list.Item
	if readOnly {
		policyItems = []list.Item{
			item{title: "List Rules", desc: "View all current policy rules"},
		}
	} else {
		policyItems = []list.Item{
			item{title: "Add Rule", desc: "Add a new policy rule"},
			item{title: "Remove Rule", desc: "Remove an existing policy rule"},
			item{title: "List Rules", desc: "View all current policy rules"},
			item{title: "Reorder Rules", desc: "Change the order of policy rules"},
		}
	}

	// Trust screen items - read-only mode only shows List Global Rules
	var trustItems []list.Item
	if readOnly {
		trustItems = []list.Item{
			item{title: "List Global Rules", desc: "View repository-wide global rules"},
		}
	} else {
		trustItems = []list.Item{
			item{title: "Add Global Rule", desc: "Add a new global rule"},
			item{title: "Remove Global Rule", desc: "Remove a global rule"},
			item{title: "Update Global Rule", desc: "Modify an existing global rule"},
			item{title: "List Global Rules", desc: "View repository-wide global rules"},
		}
	}

	m := model{
		screen:      screenChoice,
		cursorMode:  cursor.CursorBlink,
		repo:        repo,
		signer:      signer,
		policyName:  o.policyName,
		rules:       getCurrRules(o),
		globalRules: getGlobalRules(o),
		options:     o,
		readOnly:    readOnly,
		footer:      footer,

		choiceList: newMenuList("gittuf TUI", []list.Item{
			item{title: "Policy", desc: "Manage gittuf Policy"},
			item{title: "Trust", desc: "Manage gittuf Root of Trust"},
		}, delegate),
		policyScreenList: newMenuList("gittuf Policy Operations", policyItems, delegate),
		trustScreenList:  newMenuList("gittuf Trust Operations", trustItems, delegate),
		ruleList:         newMenuList("Current Rules", []list.Item{}, delegate),
		globalRuleList:   newMenuList("Global Rules", []list.Item{}, delegate),

		inputs: initInputs([]inputField{
			{"Enter Rule Name Here", "Rule Name:"},
			{"Enter Pattern Here", "Pattern:"},
			{"Enter Path to Key Here", "Authorize Key:"},
		}),
	}

	return m, nil
}

// Init initializes the input field.
func (m model) Init() tea.Cmd {
	return textinput.Blink
}

// initGlobalInputs reinitializes the input fields for global rule forms.
func (m *model) initGlobalInputs() {
	m.inputs = initInputs([]inputField{
		{"Enter Global Rule Name Here", "Rule Name:"},
		{"Enter Rule Type (threshold|block-force-pushes)", "Type:"},
		{"Enter Namespaces (comma-separated)", "Namespaces:"},
		{"Enter Threshold (if threshold type)", "Threshold:"},
	})
}

// updateRuleList updates the rule list within TUI.
func (m *model) updateRuleList() {
	items := make([]list.Item, len(m.rules))
	for i, rule := range m.rules {
		items[i] = item{title: rule.name, desc: fmt.Sprintf("Pattern: %s, Key: %s", rule.pattern, rule.key)}
	}
	m.ruleList.SetItems(items)
}

// updateGlobalRuleList updates the global rule list within TUI.
func (m *model) updateGlobalRuleList() {
	items := make([]list.Item, len(m.globalRules))
	for i, gr := range m.globalRules {
		desc := fmt.Sprintf(
			"Type: %s\nNamespaces: %s",
			gr.ruleType,
			strings.Join(gr.rulePatterns, ", "),
		)
		if gr.ruleType == tuf.GlobalRuleThresholdType {
			desc += fmt.Sprintf("\nThreshold: %d", gr.threshold)
		}
		items[i] = item{title: gr.ruleName, desc: desc}
	}
	m.globalRuleList.SetItems(items)
}
