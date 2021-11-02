# Use Golang

* Status: accepted
* Deciders: Cristian, Emil
* Date: 2021-10-28

## Context and Problem Statement

ARVOS is clearly more complex than "plumbing together a few executables" and needs to be written in *some* programming language.

Which one?

## Decision Drivers

* It needs to be a fast system-oriented programming language.
* It needs to be safe to work with.
* It needs to be easy to find talent for it.
* It needs to have good eBPF bindings.

## Considered Options

* Golang
* Python
* Rust
* C
* C++
* many more

## Decision Outcome

Chosen option: "Golang", because it is a fast system-oriented programming language, that is relatively safe (memory-wise) and popular in the cloud-native community.

## Links

* [Golang](https://golang.org/)
* [Example of Golang eBPF package](https://pkg.go.dev/github.com/cilium/ebpf)
