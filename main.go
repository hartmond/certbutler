package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/scheduler"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: cerbutler <configfile> <configfile> ...\n")
		os.Exit(1)
	}

	configs := []common.Config{}
	for _, filename := range os.Args[1:] {
		yamlBytes, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(err)
		}

		var config common.Config
		err = yaml.Unmarshal(yamlBytes, &config)
		if err != nil {
			panic(err)
		}
		configs = append(configs, config)
	}

	scheduler.RunConfig(configs)
}
