# certbutler

Tool to take care of certificate (renew, ocsp, ct)

## Idea
The certbutler runs alongside of haproxy takes care of all certificate-related stuff.

Functionalities:
- request and renew ssl certificate (with integrated dns server for validation)
- update prepared ocsp responses
- writes cert data (cerificate and ocsp responses) readable for haproxy
- configures updated cert data in running haproxy over stats socket
- monitors certificate transparency logs
- raise alarm if ceritifcate is requested by someone other

## Status
- Config processing and scheduling impelemnted
- Basic ACME functionality implemented
- Basic OCSP functionality implemented
- Nothing done for CT Log monitoring
- haproxy interaction started
- Nothing done for channel for alerts (maybe just write logs and log managment takes care of this)
