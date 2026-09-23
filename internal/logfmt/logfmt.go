// Package logfmt parses one logfmt line (key=value pairs, values optionally double-quoted with Go
// escapes), the format Loki and most Go services use for their own logs.
package logfmt

import (
	"fmt"
	"strconv"
	"strings"
)

// Parse returns the key/value pairs of line. Keys without "=" get an empty value; a later duplicate
// key overwrites an earlier one.
func Parse(line string) (map[string]string, error) {
	out := map[string]string{}
	i := 0
	for i < len(line) {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		if i >= len(line) {
			break
		}
		start := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' {
			if line[i] == '"' {
				return nil, fmt.Errorf("logfmt: quote in key at %d", i)
			}
			i++
		}
		key := line[start:i]
		if key == "" {
			return nil, fmt.Errorf("logfmt: empty key at %d", start)
		}
		if i >= len(line) || line[i] == ' ' {
			out[key] = ""
			continue
		}
		i++ // '='
		if i < len(line) && line[i] == '"' {
			j := i + 1
			for j < len(line) {
				if line[j] == '\\' {
					j += 2
					continue
				}
				if line[j] == '"' {
					break
				}
				j++
			}
			if j >= len(line) {
				return nil, fmt.Errorf("logfmt: unterminated quote for %s", key)
			}
			v, err := strconv.Unquote(line[i : j+1])
			if err != nil {
				return nil, fmt.Errorf("logfmt: value of %s: %w", key, err)
			}
			out[key] = v
			i = j + 1
			if i < len(line) && line[i] != ' ' {
				return nil, fmt.Errorf("logfmt: junk after quoted value of %s", key)
			}
			continue
		}
		j := strings.IndexByte(line[i:], ' ')
		if j < 0 {
			j = len(line) - i
		}
		out[key] = line[i : i+j]
		i += j
	}
	return out, nil
}
