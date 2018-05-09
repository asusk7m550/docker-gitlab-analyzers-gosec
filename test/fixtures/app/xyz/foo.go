package xyz

import (
	"golang.org/x/crypto/ssh"
)

func Foo() {
	_ = ssh.InsecureIgnoreHostKey()
}
