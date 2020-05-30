package main

import (
  "github.com/schulterklopfer/cyphernodeSecuredWebhook/authorization"
  "github.com/schulterklopfer/cyphernodeSecuredWebhook/secret"
  "net/http"
  "os"
)

func main() {

  if len(os.Args) < 2 {
    println( "need an url to call" )
    os.Exit(1)
  }

  url := os.Args[1]
  s, err := secret.GetSecret()

  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }

  client := &http.Client{}
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }
  req.Header.Set("Authorization", authorization.GenerateBearerTokenHeaderField(s,10) )
  _, err = client.Do(req)
  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }
}

