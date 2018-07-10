Snort (Work In Progress... there be dragons)
=========

A role to configure Snort that follows the Ansible Role Architecture guidelines.
(The guidelines are still in development, will be released in the coming weeks)

Requirements
------------

[Snort](https://www.snort.org/)

Role Variables
--------------

FIXME

Example Playbook
----------------

    ---
    - hosts: snortservers
      remote_user: root
      vars:
        fixme: fixme
      tasks:
        - include_role:
          name: maxamillion.snort


License
-------

MIT

Author Information
------------------

[Adam Miller](https://maxamillion.sh) <admiller@redhat.com>
