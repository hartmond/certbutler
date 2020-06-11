package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/scheduler"
	"gopkg.in/yaml.v3"
)

func main() {
	configs := []common.Config{}
	for _, filename := range getConfigFiles() {
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

func getConfigFiles() []string {
	if len(os.Args) > 1 {
		return os.Args[1:]
	}
	if env := os.Getenv("certbutlerconfig"); env != "" {
		return strings.Split(env, ",")
	}
	fmt.Printf("Usage: cerbutler <configfile> <configfile> ...\n")
	os.Exit(1)
	return nil
}
