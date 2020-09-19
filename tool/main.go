package main

import (
	"encoding/json"
	"fmt"
	"github.com/wii-tools/wadlib"
)

func main() {
	wad, err := wadlib.LoadWADFromFile("./RVL-Weather-v3.wad.out.wad")
	if err != nil {
		panic(err)
	}
	jsonify(wad.Ticket.Issuer)
}

func jsonify(wadStruct interface{}) {
	response, _ := json.MarshalIndent(wadStruct, "", "    ")
	fmt.Println(string(response))
}