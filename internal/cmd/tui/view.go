// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/lipgloss"
)

const (
	colorRegularText = "#FFFFFF"
	colorFocus       = "#007AFF"
	colorBlur        = "#A0A0A0"
	colorFooter      = "#11ff00"
	colorSubtext     = "#555555"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorRegularText)).
			Padding(0, 2).
			MarginTop(1).
			Bold(true)

	itemStyle = lipgloss.NewStyle().
			PaddingLeft(4).
			Foreground(lipgloss.Color(colorRegularText))

	selectedItemStyle = lipgloss.NewStyle().
				PaddingLeft(4).
				Foreground(lipgloss.Color(colorRegularText)).
				Background(lipgloss.Color(colorFocus))

	focusedStyle = lipgloss.NewStyle().
			PaddingLeft(4)

	blurredStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorBlur))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(colorRegularText))
)

// renderWithMargin wraps content in the standard margin used by all screens.
func renderWithMargin(content string) string {
	return lipgloss.NewStyle().Margin(1, 2).Render(content)
}

// renderFooter returns the footer text styled in the footer color.
func renderFooter(text string) string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(colorFooter)).Render(text)
}

// renderFormScreen renders a form screen with a title, input fields, help text, and footer.
func (m model) renderFormScreen(title, helpText string) string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for _, input := range m.inputs {
		b.WriteString(input.View() + "\n")
	}
	b.WriteString("\n" + helpText + "\n")
	b.WriteString(renderFooter(m.footer))
	return renderWithMargin(b.String())
}

// renderListScreen renders a list with help text and footer.
func (m model) renderListScreen(l list.Model, helpText string) string {
	return renderWithMargin(
		l.View() + "\n\n" +
			renderFooter(m.footer) +
			"\n" + helpText,
	)
}

// View renders the TUI.
func (m model) View() string {
	switch m.screen {
	case screenChoice:
		return renderWithMargin(m.choiceList.View() + "\n" + renderFooter(m.footer))
	case screenPolicy:
		hint := ""
		if !m.readOnly {
			hint = "Run `gittuf policy apply` to apply staged changes to the selected policy file"
		}
		return renderWithMargin(m.policyScreenList.View() + "\n" + renderFooter(m.footer) + "\n" + hint)
	case screenTrust:
		hint := ""
		if !m.readOnly {
			hint = "Run `gittuf trust apply` to apply staged changes to the selected policy file"
		}
		return renderWithMargin(m.trustScreenList.View() + "\n" + renderFooter(m.footer) + "\n" + hint)
	case screenAddRule:
		return m.renderFormScreen("Add Rule", "Press Enter to add, Esc to go back")
	case screenRemoveRule:
		return m.renderListScreen(m.ruleList, "Press Enter to remove selected rule, Esc to go back")
	case screenListRules:
		var sb strings.Builder
		sb.WriteString(titleStyle.Render("Current Rules") + "\n\n")
		for _, rule := range m.rules {
			sb.WriteString(fmt.Sprintf("- %s\n  Pattern: %s\n  Key: %s\n\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color(colorRegularText)).Bold(true).Render(rule.name),
				lipgloss.NewStyle().Foreground(lipgloss.Color(colorSubtext)).Render(rule.pattern),
				lipgloss.NewStyle().Foreground(lipgloss.Color(colorSubtext)).Render(rule.key)))
		}
		sb.WriteString("\nPress Esc to go back")
		return renderWithMargin(sb.String())
	case screenReorderRules:
		return m.renderListScreen(m.ruleList, "Use 'u' to move up, 'd' to move down, Esc to go back")
	case screenAddGlobalRule:
		return m.renderFormScreen("Add Global Rule", "Press Enter to add, Esc to go back")
	case screenListGlobalRules:
		return m.renderListScreen(m.globalRuleList, "Press Esc to go back")
	case screenUpdateGlobalRule:
		return m.renderFormScreen("Update Global Rule", "Press Enter to update, Esc to go back")
	case screenRemoveGlobalRule:
		return m.renderListScreen(m.globalRuleList, "Press Enter to remove selected global rule, Esc to go back")
	default:
		return "Unknown screen"
	}
}
