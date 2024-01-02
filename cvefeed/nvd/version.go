package nvd

import (
	"regexp"
	"strconv"
	"strings"
)

type ComponentVersion struct {
	VersionParts []string
}

var versionPattern = regexp.MustCompile(`(\d+[a-z]{1,3}$|[a-z]{1,3}[_-]?\d+|\d+|(rc|release|snapshot|beta|alpha)$)`)

func ParseVersion(version string) *ComponentVersion {
	versionParts := make([]string, 0)
	if version == "" {
		return nil
	}

	lcVersion := strings.ToLower(version)
	versionSubmatch := versionPattern.FindAllStringSubmatch(lcVersion, -1)
	for _, vs := range versionSubmatch {
		versionParts = append(versionParts, vs...)
	}
	if len(versionParts) == 0 {
		versionParts = append(versionParts, version)
	}

	return &ComponentVersion{
		VersionParts: versionParts,
	}
}

func (cv *ComponentVersion) CompareTo(v *ComponentVersion) int {
	if v == nil {
		return 1
	}
	left := cv.VersionParts
	right := v.VersionParts

	var max int
	if len(left) < len(right) {
		max = len(left)
	} else {
		max = len(right)
	}
	for i := 0; i < max; i++ {
		lStr := left[i]
		rStr := right[i]
		if lStr == rStr {
			continue
		}
		l, lerr := strconv.Atoi(lStr)
		r, rerr := strconv.Atoi(rStr)
		if lerr != nil || rerr != nil {
			comp := strings.Compare(lStr, rStr)
			if comp < 0 {
				return -1
			} else if comp > 0 {
				return 1
			}
		}
		if l < r {
			return -1
		} else if l > r {
			return 1
		}
	}
	if len(left) == max && len(right) == len(left) + 1 && right[len(right) - 1] == "0" {
		return 0
	} else if len(right) == max && len(left) == len(right) + 1 && left[len(left) - 1] == "0" {
		return 0
	} else {
		if len(left) > len(right) {
			return 1
		}
		if len(right) > len(left) {
			return -1
		}
		if len(right) == len(left) {
			return 0
		}
	}
	return 0
}
