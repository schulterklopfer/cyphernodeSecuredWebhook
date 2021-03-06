package secret

import (
  "bufio"
  "encoding/hex"
  "os"
  "regexp"
)

func GetSecret() ([]byte, error) {

  var s string

  s = os.Getenv("CN_WEBHOOKS_SECRET" )

  if s != "" {
    secretHex, err := hex.DecodeString(s)

    if err != nil {
      return nil, err
    }

    return secretHex, nil
  }

  secretPath := os.Getenv("CN_WEBHOOKS_SECRET_PATH" )
  if secretPath == "" {
    secretPath = "/run/secret/cyphernode_webhooks_secret"
  }

  file, err := os.Open(secretPath)
  if err != nil {
    return nil, err
  }
  defer file.Close()

  scanner := bufio.NewScanner(file)
  re := regexp.MustCompile(`\s`)
  for scanner.Scan() {
    line := re.ReplaceAllString( scanner.Text(), "" )
    if line == "" {
      continue
    }
    s = line
    break
  }

  if err := scanner.Err(); err != nil {
    return nil, err
  }
  secretHex, err := hex.DecodeString(s)

  if err != nil {
    return nil, err
  }

  return secretHex, nil
}