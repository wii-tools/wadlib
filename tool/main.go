package main

import (
	"github.com/wii-tools/wadlib"
	"log"
)

func main() {
	wad, err := wadlib.LoadWADFromFile("./BOOT2-64-v2.wad")
	if err != nil {
		panic(err)
	}

	log.Print(wad)
	log.Printf("WADType == WADTypeCommon? This is %t", wad.Header.WADType == wadlib.WADTypeBoot)

	wad, err = wadlib.LoadWADFromFile("./IOS80-64-6944.wad")
	if err != nil {
		panic(err)
	}

	log.Print(wad)
	log.Printf("WADType == WADTypeBoot? This is %t", wad.Header.WADType == wadlib.WADTypeCommon)
}
