# Docker-Compose deployment

With this docker-compose file, a setup is created that runs the certbutler container alongside a haproxy container.
A volume is created where the haproxy admin socket is placed in to make it accessible to the certbutler container.

To activate the admin socket, add the follwing line to the global section of the haproxy config file:
`stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners`

**Important**: Certificate Updates over the haproxy admin socket will only work if the configured certificate path is identical in the haproxy config and the certbutler config!
