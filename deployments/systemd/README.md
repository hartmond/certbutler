# Systemd service

This service file configures a systemd service to run certbutler.
In comparison to the systemd-timer deployment, the internal scheduler of certbutler is used for regular runs.

## Usage

If you use relative paths for certificate location (in config file) or for configuration file location (in systemd service file) the WorkingDirectory in the systemd service file has to be adapted to be adapted that these paths are correct.
If configuration file and certificate should be in different folders, an absolute path for the location of the configuration file can be used in the systemd service file.


- Copy `certbutler.service` to `/etc/systemd/system/`
- `systemctl daemon-reload`
- `systemctl enable --now certbutler`

From now on, systemd timer will run certbutler.
