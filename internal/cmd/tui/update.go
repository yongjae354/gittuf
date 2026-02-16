// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/gittuf/gittuf/internal/tuf"
)

// Update updates the model based on the message received.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h, v := lipgloss.NewStyle().Margin(1, 2).GetFrameSize()
		m.choiceList.SetSize(msg.Width-h, msg.Height-v)
		m.policyScreenList.SetSize(msg.Width-h, msg.Height-v)
		m.trustScreenList.SetSize(msg.Width-h, msg.Height-v)
		m.ruleList.SetSize(msg.Width-h, msg.Height-v)

	case tea.KeyMsg:
		// Global handlers (quit, back navigation)
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			m.footer = ""
			switch m.screen {
			case screenPolicy, screenTrust:
				m.screen = screenChoice
			case screenAddRule, screenRemoveRule, screenListRules, screenReorderRules:
				m.screen = screenPolicy
			case screenAddGlobalRule, screenRemoveGlobalRule, screenUpdateGlobalRule, screenListGlobalRules:
				m.screen = screenTrust
			}
			return m, nil
		}

		// Screen-specific input handling
		switch msg.String() {
		case "enter":
			return m.handleEnter()
		case "u":
			if m.screen == screenReorderRules {
				return m.handleReorderUp()
			}
		case "d":
			if m.screen == screenReorderRules {
				return m.handleReorderDown()
			}
		case "tab", "shift+tab", "up", "down":
			if m.screen == screenAddRule || m.screen == screenAddGlobalRule || m.screen == screenUpdateGlobalRule {
				m.cycleFocus(msg.String())
				return m, nil
			}
		}
	}

	// Delegate to active bubbles component per screen
	switch m.screen {
	case screenChoice:
		m.choiceList, cmd = m.choiceList.Update(msg)
	case screenPolicy:
		m.policyScreenList, cmd = m.policyScreenList.Update(msg)
	case screenTrust:
		m.trustScreenList, cmd = m.trustScreenList.Update(msg)
	case screenAddRule, screenAddGlobalRule, screenUpdateGlobalRule:
		m.inputs[m.focusIndex], cmd = m.inputs[m.focusIndex].Update(msg)
	case screenRemoveRule, screenReorderRules:
		m.ruleList, cmd = m.ruleList.Update(msg)
	case screenListGlobalRules, screenRemoveGlobalRule:
		m.globalRuleList, cmd = m.globalRuleList.Update(msg)
	}

	return m, cmd
}

// handleEnter dispatches the enter key press to the appropriate screen handler.
func (m model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenChoice:
		if i, ok := m.choiceList.SelectedItem().(item); ok {
			switch i.title {
			case "Policy":
				m.screen = screenPolicy
			case "Trust":
				m.screen = screenTrust
			}
		}
	case screenPolicy:
		if i, ok := m.policyScreenList.SelectedItem().(item); ok {
			switch i.title {
			case "Add Rule":
				m.screen = screenAddRule
				m.focusIndex = 0
				m.inputs[0].Focus()
			case "Remove Rule":
				m.screen = screenRemoveRule
				m.updateRuleList()
			case "List Rules":
				m.screen = screenListRules
			case "Reorder Rules":
				m.screen = screenReorderRules
				m.updateRuleList()
			}
		}
	case screenTrust:
		if i, ok := m.trustScreenList.SelectedItem().(item); ok {
			switch i.title {
			case "Add Global Rule":
				m.screen = screenAddGlobalRule
				m.initGlobalInputs()
			case "Remove Global Rule":
				m.screen = screenRemoveGlobalRule
				m.updateGlobalRuleList()
			case "Update Global Rule":
				m.screen = screenUpdateGlobalRule
				m.initGlobalInputs()
			case "List Global Rules":
				m.screen = screenListGlobalRules
				m.updateGlobalRuleList()
			}
		}
	case screenAddRule:
		if m.focusIndex == len(m.inputs)-1 {
			newRule := rule{
				name:    m.inputs[0].Value(),
				pattern: m.inputs[1].Value(),
				key:     m.inputs[2].Value(),
			}
			authorizedKeys := []string{m.inputs[2].Value()}
			if err := repoAddRule(m.options, newRule, authorizedKeys); err != nil {
				m.footer = fmt.Sprintf("Error adding rule: %v", err)
				return m, nil
			}
			m.rules = append(m.rules, newRule)
			m.updateRuleList()
			m.footer = "Rule added successfully!"
			m.screen = screenPolicy
		}
	case screenRemoveRule:
		if i, ok := m.ruleList.SelectedItem().(item); ok {
			if err := repoRemoveRule(m.options, rule{name: i.title}); err != nil {
				m.footer = fmt.Sprintf("Error removing rule: %v", err)
				return m, nil
			}
			for idx, r := range m.rules {
				if r.name == i.title {
					m.rules = append(m.rules[:idx], m.rules[idx+1:]...)
					break
				}
			}
			m.updateRuleList()
			m.footer = "Rule removed successfully!"
			m.screen = screenPolicy
		}
	case screenAddGlobalRule:
		if m.focusIndex == len(m.inputs)-1 {
			parts := splitAndTrim(m.inputs[2].Value())
			thr := 0
			if m.inputs[1].Value() == tuf.GlobalRuleThresholdType {
				thr, _ = strconv.Atoi(m.inputs[3].Value())
			}
			newGR := globalRule{
				ruleName:     m.inputs[0].Value(),
				ruleType:     m.inputs[1].Value(),
				rulePatterns: parts,
				threshold:    thr,
			}
			if err := repoAddGlobalRule(m.options, newGR); err != nil {
				m.footer = fmt.Sprintf("Error: %v", err)
				return m, nil
			}
			m.globalRules = append(m.globalRules, newGR)
			m.updateGlobalRuleList()
			m.footer = "Global rule added!"
			m.screen = screenTrust
		}
	case screenRemoveGlobalRule:
		if sel, ok := m.globalRuleList.SelectedItem().(item); ok {
			if err := repoRemoveGlobalRule(m.options, globalRule{ruleName: sel.title}); err != nil {
				m.footer = fmt.Sprintf("Error removing global rule: %v", err)
				return m, nil
			}
			for idx, gr := range m.globalRules {
				if gr.ruleName == sel.title {
					m.globalRules = append(m.globalRules[:idx], m.globalRules[idx+1:]...)
					break
				}
			}
			m.updateGlobalRuleList()
			m.footer = "Global rule removed!"
			m.screen = screenTrust
		}
	case screenUpdateGlobalRule:
		if m.focusIndex == len(m.inputs)-1 {
			parts := splitAndTrim(m.inputs[2].Value())
			thr := 0
			if m.inputs[1].Value() == tuf.GlobalRuleThresholdType {
				thr, _ = strconv.Atoi(m.inputs[3].Value())
			}
			updated := globalRule{
				ruleName:     m.inputs[0].Value(),
				ruleType:     m.inputs[1].Value(),
				rulePatterns: parts,
				threshold:    thr,
			}
			if err := repoUpdateGlobalRule(m.options, updated); err != nil {
				m.footer = fmt.Sprintf("Error updating global rule: %v", err)
				return m, nil
			}
			for idx, gr := range m.globalRules {
				if gr.ruleName == updated.ruleName {
					m.globalRules[idx] = updated
					break
				}
			}
			m.updateGlobalRuleList()
			m.footer = "Global rule updated!"
			m.screen = screenTrust
		}
	}
	return m, nil
}

// handleReorderUp moves the selected rule up in the list.
func (m model) handleReorderUp() (tea.Model, tea.Cmd) {
	if i := m.ruleList.Index(); i > 0 {
		m.rules[i], m.rules[i-1] = m.rules[i-1], m.rules[i]
		if err := repoReorderRules(m.options, m.rules); err != nil {
			m.footer = fmt.Sprintf("Error reordering rules: %v", err)
			return m, nil
		}
		m.updateRuleList()
		m.footer = "Rules reordered successfully!"
	}
	return m, nil
}

// handleReorderDown moves the selected rule down in the list.
func (m model) handleReorderDown() (tea.Model, tea.Cmd) {
	if i := m.ruleList.Index(); i < len(m.rules)-1 {
		m.rules[i], m.rules[i+1] = m.rules[i+1], m.rules[i]
		if err := repoReorderRules(m.options, m.rules); err != nil {
			m.footer = fmt.Sprintf("Error reordering rules: %v", err)
			return m, nil
		}
		m.updateRuleList()
		m.footer = "Rules reordered successfully!"
	}
	return m, nil
}

// cycleFocus moves focus (the cursor) between input fields in form screens.
func (m *model) cycleFocus(key string) {
	if key == "up" || key == "shift+tab" {
		if m.focusIndex > 0 {
			m.focusIndex--
			m.footer = ""
		} else {
			m.focusIndex = len(m.inputs) - 1
		}
	} else {
		if m.focusIndex < len(m.inputs)-1 {
			m.focusIndex++
		} else {
			m.focusIndex = 0
		}
	}

	for i := range m.inputs {
		if i == m.focusIndex {
			m.inputs[i].Focus()
			m.inputs[i].PromptStyle = focusedStyle
			m.inputs[i].TextStyle = focusedStyle
		} else {
			m.inputs[i].Blur()
			m.inputs[i].PromptStyle = blurredStyle
			m.inputs[i].TextStyle = blurredStyle
		}
	}
}

// splitAndTrim splits a comma-separated string and trims whitespace.
func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
