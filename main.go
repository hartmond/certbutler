package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"felix-hartmond.de/projects/certbutler/scheduler"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Printf("Usage: cerbutler <configfile>\n")
		os.Exit(1)
	}

	yamlBytes, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	configSet := scheduler.ConfigSet{}
	err = yaml.Unmarshal(yamlBytes, &configSet)
	if err != nil {
		panic(err)
	}

	scheduler.RunConfig(configSet)
}
