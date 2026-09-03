package domain

import (
	"strings"

	"github.com/google/uuid"
)

// ToDNSLabel sanitizes a hostname into a valid Magic DNS label: lowercase,
// alphanumeric and hyphens only, no leading/trailing hyphen. A hostname that
// sanitizes to nothing (empty, or entirely non-alphanumeric) falls back to a
// random label rather than colliding with every other such peer.
func ToDNSLabel(hostname string) string {
	label := strings.ToLower(hostname)
	label = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, label)
	label = strings.Trim(label, "-")
	if label == "" {
		label = "peer-" + uuid.NewString()[:8]
	}
	return label
}
