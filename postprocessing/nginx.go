package postprocessing

import (
	"os/exec"

	log "github.com/sirupsen/logrus"
)

// ProcessNginx triggers the nginx process to reload to load the new certificate
func ProcessNginx() error {
	//https://docs.nginx.com/nginx/admin-guide/basic-functionality/runtime-control/
	err := exec.Command("nginx", "-s", "reload").Run()
	if err != nil {
		return err
	}
	log.Info("Nginx reloaded successfully")
	return nil
}
