package xyz

import (
	"golang.org/x/crypto/ssh"
)

// Foo is a test function
func Foo() {
	_ = ssh.InsecureIgnoreHostKey()
}
