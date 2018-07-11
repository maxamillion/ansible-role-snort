#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Adam Miller (admiller@redhat.com)
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: snort_rule
short_description: Manage snort rules
description:
  - This module allows for addition or deletion of snort rules
version_added: "2.7"
options:
  rule:
    description:
      - "The rule definition"
    required: true
  state:
    description:
      - Add or remove a rule.
    required: true
    choices: [ "present", "absent" ]
  rules_file:
    description:
      - Path to the .rules file this rule should exist in
      required: false
      default: /etc/snort/rules/ansible_managed.rules
requirements: [ 'idstools>= 0.6.3' ]
author: "Adam Miller (@maxamillion)"
'''

EXAMPLES = '''
- snort_rule:
    rule: 'alert tcp {{home_net}} any -> {{external_net}} {{http_ports}} (msg:"APP-DETECT Absolute Software Computrace outbound connection - search.namequery.com"; flow:to_server,established; content:"Host|3A| search.namequery.com|0D 0A|"; fast_pattern:only; http_header; content:"TagId: "; http_header; metadata:policy security-ips drop, ruleset community, service http; reference:url,absolute.com/support/consumer/technology_computrace; reference:url,www.blackhat.com/presentations/bh-usa-09/ORTEGA/BHUSA09-Ortega-DeactivateRootkit-PAPER.pdf; classtype:misc-activity; sid:26287; rev:4;)'
    state: present

- snort_rule:
    rule: 'alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any'
    state: present
    rules_file: /etc/snort/rules/grab_everything_http.rules
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.firewalld import FirewallTransaction, fw_offline


def main():

    module = AnsibleModule(
        argument_spec=dict(
            rule=dict(required=True, default=None),
            state=dict(choices=['present', 'absent'], required=True),
            rules_file=dict(required=False, default='/etc/snort/rules/ansible_managed.rules),
        ),
        supports_check_mode=True
    )

if __name__ == '__main__':
    main()
