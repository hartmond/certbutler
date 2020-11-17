# CertButler

The CertBulter takes care of your certificates.
It is an ACME client that requests and renews certificates with dns-01 challenges.
It can also fetch and store OCSP responses for stapling.

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

## General Flow

Each time certbutler runs (via internal scheduler or manual run) the follwing steps happen:

### 1. Examination of nessessary tasks

First Cerbutler checks wheater certificate and/or OCSP resonse have to be updated.
Therefore, the current expirateion dates and the configuration options are checked

### 2. Updates and writing to files

When nessessary, Certificate and/or OCSP response are updated and the new versions are written to file.
Depending on the configuration Certificate and Key are stored either in one cobined or in two sepearte files.
If the target files already exist (e.g. old version of the certificate), the old files are renamed with a numer suffix.

### 3. Post-Processing is done

Post processing includes updates of web servers and/or running of a deploy hook.
If no post processors are configured, certbutler will only update the files.

## Post-Processors

Currently, the following post-processors are available:

### haproxy
The haproxy post-processor will use the nginx admin socket to send new certificates and/or OCSP responses to a running haproxy process.

For this to work successfully, different requierments have to be fullfilled:
- certbulter should be configued to store certificate an key in one file as this is the format used by haproxy
- the admin socket has to be accessible by certbulter (correct unix permissions / placed in a volume to share between containers)
- the certificate file path has to be identical in the certbutler and the haproxy configuration
- haproxy has to be already started with a certificate/OCSP response (the socket only allows updates, not new installs)

The written files are not read by haproxy during these updates, but they are needed if haproxy starts up.

### nginx
The nginx post-processor currently triggers a reload the nginx process.
This means, the certificate data is not send by certbutler.
Instead, it is read from the written files.
As nginx expects certificate and key in different files `single` should be set to false.

Nginx can gather OCSP responses itself as well as utilize a prepared response from a file.
If nginx's own mechanism should be used, `renewaldueocsp` in the cerbutler configuration can be set to `0` to disable OCSP response updates.
If prepared ones should be used, nginx can be configued to use the ones created by cerbutler with the config opion `ssl_stapling_file `.
This can be handy when `muststaple` is enabled as nginx with its own mechanism sends the first anwser after a restart without a stapled OCSP response.

### deploy-hook
The deploy hook post-processor runs a executable defined in the configuration file.
For example, it can be used to update the new certificate if the webserver has to be updated in a special way (e.g. it runs on another host) or if the updated certificate has to be copied to other cluster nodes in addition to local webserver update.

## Run as service / Deployment
There are different ways/components to run certbutler as a serivce.
Varios options can be found in the deployments folder:
- [Docker conainer with docker-compose for use with haproxy](deployments/docker/README.md)
- [Systemd-Service](deployments/systemd/README.md)
- [Systemd-Service with Timer](deployments/systemd-timer/README.md)
- [Ansible playbook for systemd deployment](deployments/ansible/README.md)

## Troubeshooting

**Some strange error with yaml**

There is probably a syntax error in the configuration file.
Check the config file with a yaml validator.
Maybe the identations of the config blocks are are wrong or a string with special chars is not quoted.

**It does not work / Nothing happens after "Waiting for authorizations..."**

The DNS validation seems to have problems.
Double-check if the "_acme-challenge" DNS records are set correctly and wheather DNS requests can reach certbutler (is port 53/udp open in the firewall).
You can debug connectivity issues by watching for the incomming requests from the acme endpoint (e.g. with tcpdump/wireshark).
If no request reach your host check if the NS records have successfully propagated (maybe wait a day) and wheather you can  resolve the TXT records hosted by certbutler yourself from another server.
