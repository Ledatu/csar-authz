package engine

import "strings"

// MatchResource checks if a URL path matches a resource pattern.
//
// Pattern syntax:
//   - Exact segments match literally: /api/v1/users matches /api/v1/users
//   - Single wildcard (*) matches exactly one path segment: /api/*/users matches /api/v1/users
//   - Double wildcard (**) matches zero or more segments: /api/** matches /api, /api/v1, /api/v1/users/123
//   - A standalone "**" or "/**" matches everything
func MatchResource(pattern, path string) bool {
	patParts := splitPath(pattern)
	pathParts := splitPath(path)
	return matchParts(patParts, pathParts)
}

// MatchAction checks if an action matches a permission action.
// "*" matches any action. Otherwise, case-insensitive exact match.
func MatchAction(permAction, reqAction string) bool {
	if permAction == "*" {
		return true
	}
	return strings.EqualFold(permAction, reqAction)
}

// splitPath splits a path by "/" and removes empty segments.
func splitPath(p string) []string {
	parts := strings.Split(p, "/")
	result := parts[:0]
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// matchParts recursively matches pattern parts against path parts.
func matchParts(pattern, path []string) bool {
	pi, pj := 0, 0

	for pi < len(pattern) {
		if pattern[pi] == "**" {
			// If ** is the last pattern segment, it matches everything remaining.
			if pi == len(pattern)-1 {
				return true
			}

			// Try matching the rest of the pattern at every possible position.
			for k := pj; k <= len(path); k++ {
				if matchParts(pattern[pi+1:], path[k:]) {
					return true
				}
			}
			return false
		}

		// No more path segments but pattern still has non-** segments.
		if pj >= len(path) {
			return false
		}

		if pattern[pi] == "*" {
			// Single wildcard: matches exactly one segment.
			pi++
			pj++
			continue
		}

		// Exact match.
		if pattern[pi] != path[pj] {
			return false
		}
		pi++
		pj++
	}

	// Pattern consumed: path must also be fully consumed.
	return pj == len(path)
}
