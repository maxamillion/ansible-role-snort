IDS (Work In Progress... there be dragons)
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
    - name: test snort_rule module
      hosts: snort
      remote_user: root

      vars:
        ids_provider: snort

      tasks:
        - name: Add an ids role
          include_role:
            name: "ids-rule"
          vars:
            ids_rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SERVER-SAMBA Samba write andx command memory leak attempt"; flow:to_server, established; content:"|FF 53 4D 42 2F|"; depth:5; offset:4; byte_extract:2,44,remaining,relative,little; byte_test:2,>,remaining,2,relative,little; reference:cve,2017-12163; reference:url,samba.org/samba/security/CVE-2017-12163.html; classtype:attempted-user; sid:45069; rev:1;)'
            ids_rules_file: '/etc/snort/rules/server-samba.rules'
            ids_rule_state: present
        - name: Remove ids rule
          include_role:
            name: "ids-rule"
          vars:
            ids_rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SERVER-SAMBA Samba write andx command memory leak attempt"; flow:to_server, established; content:"|FF 53 4D 42 2F|"; depth:5; offset:4; byte_extract:2,44,remaining,relative,little; byte_test:2,>,remaining,2,relative,little; reference:cve,2017-12163; reference:url,samba.org/samba/security/CVE-2017-12163.html; classtype:attempted-user; sid:45069; rev:1;)'
            ids_rules_file: '/etc/snort/rules/server-samba.rules'
            ids_rule_state: absent
        - name: Remove ids rule again (idempotent)
          include_role:
            name: "ids-rule"
          vars:
            ids_rule: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SERVER-SAMBA Samba write andx command memory leak attempt"; flow:to_server, established; content:"|FF 53 4D 42 2F|"; depth:5; offset:4; byte_extract:2,44,remaining,relative,little; byte_test:2,>,remaining,2,relative,little; reference:cve,2017-12163; reference:url,samba.org/samba/security/CVE-2017-12163.html; classtype:attempted-user; sid:45069; rev:1;)'
            ids_rules_file: '/etc/snort/rules/server-samba.rules'
            ids_rule_state: absent

License
-------

MIT

Author Information
------------------

[Adam Miller](https://maxamillion.sh) <admiller@redhat.com>
