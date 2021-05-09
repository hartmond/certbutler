package common

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

func LoadConfig(filename string) (config Config, err error) {
	yamlBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(yamlBytes, &config)
	if err != nil {
		return
	}
	return
}
