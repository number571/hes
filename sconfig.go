package main

import (
	"os"
	"encoding/json"
	"io/ioutil"
)

type CFG struct {
	Pasw  string      `json:"pasw"`
	Conns [][2]string `json:"conns"`
	// conn[0] = addr
	// conn[1] = pasw
}

func NewCFG(filename string) *CFG {
	var config = new(CFG)
	if !fileIsExist(filename) {
		err := ioutil.WriteFile(filename, serialize(config), 0644)
		if err != nil {
			return nil
		}
	}
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil
	}
	err = json.Unmarshal(content, config)
	if err != nil {
		return nil
	}
	return config
}

func fileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}
