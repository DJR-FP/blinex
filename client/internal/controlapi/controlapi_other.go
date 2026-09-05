//go:build !windows

package controlapi

// grantSocketAccess is a no-op outside Windows — Unix socket permissions are
// already handled by the os.Chmod call in Serve.
func grantSocketAccess(_ string) {}
