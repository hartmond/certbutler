# Systemd service (timer)

These files configure a systemd timer to certbutler regularly.

For this deployment type, `runintervalminutes` in the configuration files has to be set to `0` as systemd takes care of the regular runs.

## Usage

- This assumes that you have your config in `/etc/certbutler/config.yaml`, otherwise adapt the config path in the service file.
- Copy `certbutler.service` and `certbutler.timer` to `/etc/systemd/system/`
- `systemctl daemon-reload`
- `systemctl enable --now certbutler.timer`

From now on, a daily systemd timer will run certbutler.
