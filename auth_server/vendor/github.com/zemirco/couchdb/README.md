
# couchdb

[![Build Status](https://travis-ci.org/zemirco/couchdb.svg)](https://travis-ci.org/zemirco/couchdb)
[![Coverage Status](https://coveralls.io/repos/github/zemirco/couchdb/badge.svg?branch=master)](https://coveralls.io/github/zemirco/couchdb?branch=master)
[![GoDoc](https://godoc.org/github.com/zemirco/couchdb?status.svg)](https://godoc.org/github.com/zemirco/couchdb)

CouchDB client for Go.

## Example

```go
package main

import (
	"log"

	"github.com/zemirco/couchdb"
)

func main() {
	// create a new client
	client, err := couchdb.NewClient("http://127.0.0.1:5984/")
	if err != nil {
		panic(err)
	}
	// get some information about your CouchDB
	info, err := client.Info()
	if err != nil {
		panic(err)
	}
	log.Println(info)

}
```

More
[examples](https://github.com/zemirco/couchdb/blob/master/example/example.go).

## Test

`go test`

## License

MIT
