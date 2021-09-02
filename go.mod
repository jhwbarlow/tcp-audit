module github.com/jhwbarlow/tcp-audit

go 1.15

//replace github.com/jhwbarlow/tcp-audit-common => ../tcp-audit-common

require (
	github.com/jhwbarlow/tcp-audit-common v0.0.0-20210831195703-56b4e4c3ea54
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
)
