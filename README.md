# CertButler

The CertBulter takes care of your certificates.
It is an ACME client that requests and renews certificates with dns-01 challenges.
When used with haproxy it also handles the renew of OCSP responses for stapling.
In the future, CertButler will also allow basic CT log monitoring.

## Why another ACME client

Wildcard certificates without pain.

Sounds simple, but I have not found a client which covered my scenario.
I wanted to have wildcard certificates (therefore I need to use the dns-01 challenge) but not want to have DNS hosting credentials on my host and do not want to have struggle with propagation delays.
Therefore, I delegate the _acme-challenge subdomain to my host and then the acme client can open a DNS server and provide the challenge itself.
This takes away all credentials and propagation problems.
As having these challenges on a fixed subdomain seems to be built with this implementation in mind, I wonder why no existing client supports this.
So, here it my own one: CertButler!

## Usage

### DNS Setup
An NS Record for the subdomain ``_acme-challenge.<DOMAIN>`` below all domains, which should be included has to be created that points to the host CertButler is running on.

### Configuration
CertButler is configured with yaml configuration files.
It is possible to configure multiple certificates.
In this case, one config file per certificate has to be provided.

### Running the Butler
``./certbutler <config1>.yaml <config2>.yaml``

The list of config files can also be provided via an environment variable ``certbutlerconfig=<config1>.yaml,<config2>.yaml``.
This can be used when using the Docker container.

### Run as service / Deployment
There are different ways/components to run certbutler as a serivce.
Varios options are in the deployments folder.

Currenty, the following ones exist:
- [Docker conainer with docker-compose for use with haproxy](deployments/docker/README.md)
- [Systemd-Service](deployments/systemd/README.md)
- [Systemd-Service with Timer](deployments/systemd-timer/README.md)
- [Ansible playbook for systemd deployment](deployments/ansible/README.md)

## Webserver integration
There are modes for haproxy and nginx.

In haproxy mode, the Butler will renew certificates and OCSP responses.
Updated certificates and responses are sent to the running haproxy process over the admin socket.

In nginx mode, the Butler will not update OCSP responses as nginx updates these itself. After a certificate was updated, nginx will be triggered to reload its configuration to use the new certificate.

Depending on the mode, certificate, chain and key will be stored in one file (haproxy) or different files (nginx).
