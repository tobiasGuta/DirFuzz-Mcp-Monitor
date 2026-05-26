package main

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	c := lipgloss.Color("#50FA7B") // DraculaGreen
	
	// Left part: standard rounded border
	leftBorder := lipgloss.RoundedBorder()
	leftBorder.TopRight = "┬"
	leftBorder.BottomRight = "┴"
	
	leftStyle := lipgloss.NewStyle().
		Foreground(c).
		Background(lipgloss.Color("#1E1E2E")).
		Border(leftBorder).
		BorderForeground(c).
		BorderBackground(lipgloss.Color("#1E1E2E")).
		Padding(0, 1)

	// Right part: full border, but left edge is empty string
	rightBorder := lipgloss.RoundedBorder()
	rightBorder.TopLeft = "─"
	rightBorder.BottomLeft = "─"
	rightBorder.Left = ""
	
	rightStyle := lipgloss.NewStyle().
		Background(lipgloss.Color("#1E1E2E")). // DARK BACKGROUND!
		Foreground(c). // COLORED TEXT
		Border(rightBorder). // True for all edges
		BorderForeground(c).
		BorderBackground(lipgloss.Color("#1E1E2E")). // DARK BORDER BACKGROUND!
		Padding(0, 1).
		Bold(true)

	left := leftStyle.Render("✓ 2xx")
	right := rightStyle.Render("47")

	badge := lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	fmt.Println(badge)
}
