//go:build !linux

package acl

import commonv1 "github.com/meshnet/gen/common/v1"

func EnsureChain(_ string) error                      { return nil }
func ApplyRules(_ []*commonv1.Rule, _ string) error   { return nil }
func RemoveChain(_ string)                            {}
