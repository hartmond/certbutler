certbutler-ansible
=========

This role deploys certbutler to a system

Requirements
------------

In order to function, it is required that your domain's `_acme-challenge` DNS zone NS entry points to the server running certbutler.
Also, you need to provide your own certbutler binary and config, see `tasks/main.yml` and the example config coming along certbutler.

Role Variables
--------------

There are currently no role variables. Make sure to adapt the configuration files.


Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: username.rolename, x: 42 }

License
-------

GPL 3.0

Author Information
------------------

Project page: https://github.com/hartmond/certbutler
Felix Hartmond (https://github.com/hartmond)
Michael Eder (https://github.com/edermi)

