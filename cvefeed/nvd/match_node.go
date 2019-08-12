package nvd

import (
	"log"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

// Matcher returns an object which knows how to match attributes
func (node *NVDCVEFeedJSON10DefNode) Matcher() wfn.Matcher {
	if node == nil {
		return nil
	}

	var ms []wfn.Matcher
	for _, cm := range node.CPEMatch {
		if cm != nil {
			if m, err := cm.Matcher(); err == nil {
				ms = append(ms, m)
			}
		}
	}
	for _, child := range node.Children {
		if child != nil {
			if m := child.Matcher(); m != nil {
				ms = append(ms, m)
			}
		}
	}

	if len(ms) == 0 {
		return nil
	}

	var m wfn.Matcher

	switch strings.ToUpper(node.Operator) {
	default:
		log.Printf("unknown operator, defaulting to OR: got %q", node.Operator)
		fallthrough
	case "OR":
		m = wfn.MatchAny(ms...)
	case "AND":
		m = wfn.MatchAll(ms...)
	}

	if node.Negate {
		m = wfn.DontMatch(m)
	}

	return m
}
