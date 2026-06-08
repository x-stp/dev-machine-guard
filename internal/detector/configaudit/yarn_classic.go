package configaudit

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseYarnClassic parses a yarn v1 `.yarnrc` file into ordered YarnEntries.
//
// Format reference (yarn v1):
//   - One entry per line: `key value` (whitespace-separated), or `key "quoted value"`.
//   - `#` and `;` at the start of a non-whitespace line begin a comment.
//   - URI-prefixed keys (`//npm.example.com/:_authToken`) are valid.
//   - Boolean / numeric / string values are all serialized as bare tokens;
//     we don't try to coerce types — the audit just records the textual form.
//
// The parser is tolerant: malformed lines surface as best-effort entries
// rather than aborting the whole parse, mirroring npmrc_parse.go's behavior.
func parseYarnClassic(data []byte) []model.YarnEntry {
	var entries []model.YarnEntry

	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}

		// yarn v1 uses whitespace as the key/value separator; the value may
		// be quoted. Split on the first run of whitespace.
		key, value, quoted := splitYarnClassicLine(trimmed)
		if key == "" {
			continue
		}
		entries = append(entries, buildYarnEntry(key, value, quoted, lineNum))
	}

	return entries
}

// splitYarnClassicLine extracts the (key, value, quoted) triple from a
// yarn v1 line. Values surrounded by matching double quotes are unwrapped;
// the quoted flag preserves the fact that they were quoted in the source.
func splitYarnClassicLine(line string) (string, string, bool) {
	// Locate the first whitespace run.
	idx := strings.IndexAny(line, " \t")
	if idx < 0 {
		// Key with no value.
		return line, "", false
	}
	key := line[:idx]
	rest := strings.TrimLeft(line[idx:], " \t")
	if rest == "" {
		return key, "", false
	}
	if len(rest) >= 2 && rest[0] == '"' && rest[len(rest)-1] == '"' {
		return key, rest[1 : len(rest)-1], true
	}
	return key, rest, false
}

// yarnClassicAuthSuffixes are the trailing key segments that mean "this is a
// credential" in a yarn v1 file. We compare against the suffix after the
// final `:` so URI-prefixed keys like `//npm.example.com/:_authToken` match.
var yarnClassicAuthSuffixes = []string{
	"_auth",
	"_authtoken",
	"_password",
	"npmauthtoken",
}

// isYarnClassicAuthKey reports whether key denotes a credential by the
// classic v1 syntax.
func isYarnClassicAuthKey(key string) bool {
	suffix := key
	if idx := strings.LastIndex(key, ":"); idx >= 0 {
		suffix = key[idx+1:]
	}
	suffix = strings.ToLower(suffix)
	for _, s := range yarnClassicAuthSuffixes {
		if suffix == s {
			return true
		}
	}
	return false
}

// buildYarnEntry produces a YarnEntry from a key/value, classifying auth /
// env-ref / quoted state and redacting credentials before display.
func buildYarnEntry(key, value string, quoted bool, lineNum int) model.YarnEntry {
	isAuth := isYarnClassicAuthKey(key) || isYarnBerryAuthKey(key)
	envRefVars, isEnvRef := extractEnvRefs(value)

	display := value
	if isAuth && !isEnvRef && value != "" {
		display = redactSecret(value)
	}

	return model.YarnEntry{
		Key:          key,
		DisplayValue: display,
		LineNum:      lineNum,
		IsAuth:       isAuth,
		IsEnvRef:     isEnvRef,
		EnvRefVars:   envRefVars,
		ValueSHA256:  hashValue(value),
		Quoted:       quoted,
	}
}
