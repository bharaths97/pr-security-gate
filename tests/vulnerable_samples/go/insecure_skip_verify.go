package main

import "crypto/tls"

var insecureConfig = tls.Config{InsecureSkipVerify: true}
