package postprocessing

import (
	"os/exec"
)

// ProcessNginx triggers the nginx process to reload to load the new certificate
func ProcessNginx() error {
	//https://docs.nginx.com/nginx/admin-guide/basic-functionality/runtime-control/
	return exec.Command("nginx", "-s", "reload").Run()
}
