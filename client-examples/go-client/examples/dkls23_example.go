package main

import (
    "fmt"
    "github.com/0xCarbon/libtss/client-examples/go-client/dkls23"
)

func main() {
    input := `{"session":{"parameters":{"threshold":2,"share_count":2},"party_index":1,"session_id":[155,91,34,177,234,249,164,92,254,10,140,65,30,135,113,112,137,57,36,209,201,197,182,252,49,111,29,209,53,68,140,219]}}`
    result := dkls23.GenerateKeySharesPhase1(input)
    fmt.Println("Result:", result)
}
