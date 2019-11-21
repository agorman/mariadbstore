# mariadbstore

[![GoDoc](https://godoc.org/github.com/agorman/mariadbstore?status.svg)](https://godoc.org/github.com/agorman/mariadbstore)

A session store for [gorilla/sessions](https://github.com/gorilla/sessions)

Installation
===========

`go get github.com/agorman/mariadbstore`

Example
=====    

    package main

    import (
  	    "github.com/agorman/mariadbstore"
    )

    func main() {
        store, err := mariadbstore.NewMariadbStore(db, "sessions", []byte("secret"))
        if err != nil {
            panic(err)
        }
    }