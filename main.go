package main

import (
  "crypto/hmac"
  "crypto/sha256"
  "encoding/base64"
  "github.com/schulterklopfer/cyphernodeSecuredWebhook/getSecret"
  "net/http"
  "os"
  "fmt"
  "time"
)

func main() {

  if len(os.Args) < 2 {
    println( "need an url to call" )
    os.Exit(1)
  }

  url := os.Args[1]

  secret, err := getSecret.GetSecret()

  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }

  header := "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  payload := fmt.Sprintf("{\"exp\":%d}", time.Now().Unix()+int64(10) )
  message := base64.URLEncoding.EncodeToString( []byte(header) )+"."+base64.URLEncoding.EncodeToString( []byte(payload) )

  mac := hmac.New(sha256.New, secret)
  mac.Write([]byte(message))
  sig := base64.URLEncoding.EncodeToString( mac.Sum(nil) )

  bearerToken := message+"."+sig

  client := &http.Client{}
  req, err := http.NewRequest("GET", url, nil)
  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }
  req.Header.Set("Authorization", "Bearer "+bearerToken)
  _, err = client.Do(req)
  if err != nil {
    println( err.Error() )
    os.Exit(1)
  }
}

