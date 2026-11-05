//go:build !windows

package sysproxy

// Saved is the previous proxy setting.
type Saved struct{}

func Enable(string) (*Saved, error) { return nil, ErrUnsupported }
func Restore(*Saved) error          { return nil }
