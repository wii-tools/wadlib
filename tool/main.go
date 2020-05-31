package main

import (
	"encoding/json"
	"fmt"
	"github.com/wii-tools/wadlib"
)

func main() {
	wad, err := wadlib.LoadWADFromFile("./BOOT2-64-v2.wad")
	if err != nil {
		panic(err)
	}

	//log.Print(wad)
	//log.Printf("WADType == WADTypeCommon? This is %t", wad.Header.WADType == wadlib.WADTypeBoot)

	//wad, err := wadlib.LoadWADFromFile("./IOS80-64-6944.wad")
	//if err != nil {
	//	panic(err)
	//}

	jsonify(wad.Header)
	jsonify(wad.Ticket)
	jsonify(wad.TMD)


	//log.Print(wad)
	//log.Printf("WADType == WADTypeBoot? This is %t", wad.Header.WADType == wadlib.WADTypeCommon)
}

func jsonify(wadStruct interface{}) {
	response, _ := json.MarshalIndent(wadStruct, "", "    ")
	fmt.Println(string(response))
}