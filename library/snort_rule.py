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
from ansible.module_utils._text import to_text

from idstools import rule

def main():

    module = AnsibleModule(
        argument_spec=dict(
            rule=dict(required=True, default=None),
            state=dict(choices=['present', 'absent'], required=True),
            rules_file=dict(required=False, default='/etc/snort/rules/ansible_managed.rules'),
        ),
        supports_check_mode=True
    )

    matched_rules = [
        snort_rule for snort_rule in rule.parse_file(module.params['rules_file'])
        if snort_rule == to_text(rule.parse(module.params['rule']))
    ]
    rule_found = True if matched_rules else False

    if module.params['state'] == 'present' and rule_found:
        module.exit_json(
            msg="Rule '{}' already present in rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=False
        )
    elif module.params['state'] == 'present' and not rule_found:
        if module.check_mode:
            module.exit_json(
                msg="Rule '{}' would be added to rules_file {}".format(module.params['rule'], module.params['rules_file']),
                changed=True
            )

        with open(module.params['rules_file'], 'a') as rules_file:
            rules_file.write(to_text(rule.parse(module.params['rule'])))

        module.exit_json(
            msg="Rule '{}' added to rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=True
        )

    if module.params['state'] == 'absent' and not rule_found:
        module.exit_json(
            msg="Rule '{}' does not exist in rules_file {}".format(module.params['rule'], module.params['rules_file']),
            changed=False
        )
    elif module.params['state'] == 'absent' and rule_found:
        orig_file_contents = []
        with open(module.params['rules_file'], 'r') as rules_file:
            orig_file_contents = rules_file.readlines()

        new_file_contents = [
            line for line in orig_file_contents
            if rule.parse(module.params['rule']) != rule.parse(line)
        ]

        if module.check_mode:
            if len(orig_file_contents) != len(new_file_contents):
                module.exit_json(
                    msg=


        with open(module.params['rules_file'], 'w'



if __name__ == '__main__':
    main()
