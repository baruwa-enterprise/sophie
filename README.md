# sophie

Golang Sophie Client

[![Ci](https://github.com/baruwa-enterprise/sophie/workflows/Ci/badge.svg)](https://github.com/baruwa-enterprise/sophie/actions?query=workflow%3ACi)
[![codecov](https://codecov.io/gh/baruwa-enterprise/sophie/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/sophie)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/sophie)](https://goreportcard.com/report/github.com/baruwa-enterprise/sophie)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/sophie?status.svg)](https://godoc.org/github.com/baruwa-enterprise/sophie)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

sophie is a Golang library and cmdline tool that implements the
Sophie client protocol.

## Requirements

* Golang 1.10.x or higher

## Getting started

### Sophie client

The sophie client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/sophie/cmd/sophiescan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/sophiescan
```

### Sophie library

To install the library

```console
go get github.com/baruwa-enterprise/sophie
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/sophie"
```

### Testing

``make test``

## License

MPL-2.0
