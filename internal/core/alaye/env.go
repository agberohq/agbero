package alaye

import "os"

const (
	envDelimiter = "="
	emptyString  = ""
)

// CompileEnv merges levels of environment variables into a final process environment.
// It resolves each value against the previously merged layers to support variable inheritance.
func CompileEnv(globalEnv, routeEnv, taskEnv map[string]Value) []string {
	res := make(map[string]string)

	for _, env := range os.Environ() {
		if key, val, ok := splitEnv(env); ok {
			res[key] = val
		}
	}

	resolver := func(key string) string {
		return res[key]
	}

	for k, v := range globalEnv {
		res[k] = v.Resolve(resolver)
	}

	for k, v := range routeEnv {
		res[k] = v.Resolve(resolver)
	}

	for k, v := range taskEnv {
		res[k] = v.Resolve(resolver)
	}

	out := make([]string, 0, len(res))
	for k, v := range res {
		out = append(out, k+envDelimiter+v)
	}
	return out
}

// splitEnv divides a system environment string into its key and value components.
// It returns the pair and a boolean indicating if the string contained the delimiter.
func splitEnv(env string) (key, val string, ok bool) {
	for i := 0; i < len(env); i++ {
		if env[i] == '=' {
			return env[:i], env[i+1:], true
		}
	}
	return emptyString, emptyString, false
}
