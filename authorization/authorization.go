package authorization

import (
  "crypto/hmac"
  "crypto/sha256"
  "encoding/base64"
  "encoding/json"
  "errors"
  "fmt"
  "strings"
  "time"
)

type BearerTokenHeader struct {
  Typ string
  Alg string
}

type BearerTokenPayload struct {
  Exp int64
}

func IsValidBearerTokenHeaderField( bearerToken string, secret []byte ) (bool, error) {
  bearerToken = strings.Trim( bearerToken," " )

  bearerTokenParts := strings.Split(bearerToken, " ")
  if len(bearerTokenParts) != 2 {
    return false, errors.New("invalid bearer token part size")
  }

  for i:=0; i<len(bearerTokenParts); i++ {
    bearerTokenParts[i] = strings.Trim( bearerTokenParts[i]," " )
  }

  if strings.ToLower(bearerTokenParts[0]) != "bearer" {
    return false, errors.New("invalid type")
  }

  signedMessage := bearerTokenParts[1]

  signedMessageParts := strings.Split(signedMessage, ".")

  if len(signedMessageParts) != 3 {
    return false, errors.New("invalid signed message part size")
  }

  headerJsonBytes, err := base64.URLEncoding.DecodeString( signedMessageParts[0] )

  if err != nil {
    return false, err
  }

  payloadJsonBytes, err := base64.URLEncoding.DecodeString( signedMessageParts[1] )

  if err != nil {
    return false, err
  }

  var header BearerTokenHeader

  if err = json.Unmarshal( headerJsonBytes, &header ); err != nil {
    return false, err
  }

  var payload BearerTokenPayload

  if err = json.Unmarshal( payloadJsonBytes, &payload ); err != nil {
    return false, err
  }

  now := time.Now().Unix()

  if now > payload.Exp {
    // token is expired
    return false, errors.New("bearer token has expired")
  }

  if header.Typ != "JWT" {
    return false, errors.New("unknown type in bearer token")
  }

  if header.Alg != "HS256" {
    return false, errors.New("unknown hashing algorithm in bearer token")
  }

  receivedMAC, err := base64.URLEncoding.DecodeString(signedMessageParts[2])


  mac := hmac.New(sha256.New, secret)
  mac.Write([]byte(signedMessageParts[0]+"."+signedMessageParts[1]))
  expectedMAC := mac.Sum(nil)

  return hmac.Equal(receivedMAC, expectedMAC), nil

}

func GenerateBearerTokenHeaderField( secret []byte, validForSeconds uint ) string {

  header := "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
  payload := fmt.Sprintf("{\"exp\":%d}", time.Now().Unix()+int64(validForSeconds) )
  message := base64.URLEncoding.EncodeToString( []byte(header) )+"."+base64.URLEncoding.EncodeToString( []byte(payload) )

  mac := hmac.New(sha256.New, secret)
  mac.Write([]byte(message))
  sig := base64.URLEncoding.EncodeToString( mac.Sum(nil) )

  return "Bearer "+message+"."+sig
}