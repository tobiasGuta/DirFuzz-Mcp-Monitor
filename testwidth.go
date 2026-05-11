package main
import (
"fmt"
"github.com/charmbracelet/lipgloss"
)
func main() {
 s1 := lipgloss.NewStyle().Width(10)
 s2 := lipgloss.NewStyle().Width(10).Padding(0, 1)
 s3 := lipgloss.NewStyle().Width(10).Border(lipgloss.RoundedBorder())
 s4 := lipgloss.NewStyle().Width(10).Padding(0, 1).Border(lipgloss.RoundedBorder())
 s5 := lipgloss.NewStyle().Width(10).Margin(0, 1).Padding(0, 1).Border(lipgloss.RoundedBorder())
 fmt.Println(lipgloss.Width(s1.Render("a")))
 fmt.Println(lipgloss.Width(s2.Render("a")))
 fmt.Println(lipgloss.Width(s3.Render("a")))
 fmt.Println(lipgloss.Width(s4.Render("a")))
 fmt.Println(lipgloss.Width(s5.Render("a")))
}
