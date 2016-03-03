#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Matt Hite <mhite@hotmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: bigip_ssl_client_profile
short_description: "Manages F5 BIG-IP LTM pools"
description:
    - "Manages F5 BIG-IP LTM pools via iControl SOAP API"
version_added: "1.2"
author: "Matt Hite (@mhite)"
notes:
    - "Requires BIG-IP software version >= 11"
    - "F5 developed module 'bigsuds' required (see http://devcentral.f5.com)"
    - "Best run as a local_action in your playbook"
requirements:
    - bigsuds
options:
    server:
        description:
            - BIG-IP host
        required: true
        default: null
        choices: []
        aliases: []
    user:
        description:
            - BIG-IP username
        required: true
        default: null
        choices: []
        aliases: []
    password:
        description:
            - BIG-IP password
        required: true
        default: null
        choices: []
        aliases: []
    validate_certs:
        description:
            - If C(no), SSL certificates will not be validated. This should only be used
              on personally controlled sites using self-signed certificates.
        required: false
        default: 'yes'
        choices: ['yes', 'no']
        version_added: 2.0
    state:
        description:
            - State of SSL client profile
        required: false
        default: present
        choices: ['present', 'absent']
        aliases: []
    name:
        description:
            - SSL client profile name
        required: true
        default: null
        choices: []
        aliases: []
    partition:
        description:
            - Partition of SSL client profile member
        required: false
        default: 'Common'
        choices: []
        aliases: []
    certificate:
        description:
            - SSL Certificate file on the F5
        required: false
        default: null
        choices: []
        aliases: []  
    key:
        description:
            - SSL key file on the F5
        required: false
        default: null
        choices: []
        aliases: []
    chain:
        description:
            - SSL chain certificate file on the F5
        required: false
        default: null
        choices: []
        aliases: []
    parent_profile:
        description:
            - The parent profile for this SSL client profile
        required: false
        default: clientssl
        choices: []
        aliases: []
'''

EXAMPLES = '''

## playbook task examples:

---
# file bigip-test.yml
# ...
- hosts: localhost
  tasks:
  - name: Create pool
    local_action: >
      bigip_pool
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=present
      name=matthite-pool
      partition=matthite
      lb_method=least_connection_member
      slow_ramp_time=120

  - name: Modify load balancer method
    local_action: >
      bigip_pool
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=present
      name=matthite-pool
      partition=matthite
      lb_method=round_robin

- hosts: bigip-test
  tasks:
  - name: Add pool member
    local_action: >
      bigip_pool
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=present
      name=matthite-pool
      partition=matthite
      host="{{ ansible_default_ipv4["address"] }}"
      port=80

  - name: Remove pool member from pool
    local_action: >
      bigip_pool
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=absent
      name=matthite-pool
      partition=matthite
      host="{{ ansible_default_ipv4["address"] }}"
      port=80

- hosts: localhost
  tasks:
  - name: Delete pool
    local_action: >
      bigip_pool
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=absent
      name=matthite-pool
      partition=matthite

'''

def profile_list(api):
    """
        List all SSL client profiles in a partition
    """
    return api.LocalLB.ProfileClientSSL.get_list()


def profile_exists(api, name, partition):
    ssl_name = "/{}/{}".format(partition,name)
    return ssl_name in profile_list(api)


def create_profile(api, name, partition, certificate, key, chain, parent_profile):
    api.System.Session.set_active_folder("/" + partition)

    certificate_name = "/{}/{}.crt".format(partition, certificate)
    key_name = "/{}/{}.key".format(partition, key)
    chain_name = "/{}/{}.crt".format(partition, chain)
    common_chain_name = "/Common/{}.crt".format(chain)

    api.LocalLB.ProfileClientSSL.create_v2(profile_names=[name],
        certs=[{'value': certificate_name, 'default_flag': False}],
        keys=[{'value': key_name, 'default_flag': False}])
    
    if chain is not None:
        api.LocalLB.ProfileClientSSL.set_chain_file_v2(
            profile_names=[name],
            chains=[{'value': chain_name, 'default_flag': False}])

    if parent_profile is not None:
        api.LocalLB.ProfileClientSSL.set_default_profile(
            profile_names=[name], defaults=[parent_profile])
    

def remove_profile(api, name, partition):
    ssl_name = "/{}/{}".format(partition,name)
    api.LocalLB.ProfileClientSSL.delete_profile( profile_names = [ ssl_name ] )


def get_lb_method(api, pool):
    lb_method = api.LocalLB.Pool.get_lb_method(pool_names=[pool])[0]
    lb_method = lb_method.strip().replace('LB_METHOD_', '').lower()
    return lb_method

def set_lb_method(api, pool, lb_method):
    lb_method = "LB_METHOD_%s" % lb_method.strip().upper()
    api.LocalLB.Pool.set_lb_method(pool_names=[pool], lb_methods=[lb_method])

def get_monitors(api, pool):
    result = api.LocalLB.Pool.get_monitor_association(pool_names=[pool])[0]['monitor_rule']
    monitor_type = result['type'].split("MONITOR_RULE_TYPE_")[-1].lower()
    quorum = result['quorum']
    monitor_templates = result['monitor_templates']
    return (monitor_type, quorum, monitor_templates)

def set_monitors(api, pool, monitor_type, quorum, monitor_templates):
    monitor_type = "MONITOR_RULE_TYPE_%s" % monitor_type.strip().upper()
    monitor_rule = {'type': monitor_type, 'quorum': quorum, 'monitor_templates': monitor_templates}
    monitor_association = {'pool_name': pool, 'monitor_rule': monitor_rule}
    api.LocalLB.Pool.set_monitor_association(monitor_associations=[monitor_association])

def get_slow_ramp_time(api, pool):
    result = api.LocalLB.Pool.get_slow_ramp_time(pool_names=[pool])[0]
    return result

def set_slow_ramp_time(api, pool, seconds):
    api.LocalLB.Pool.set_slow_ramp_time(pool_names=[pool], values=[seconds])

def get_action_on_service_down(api, pool):
    result = api.LocalLB.Pool.get_action_on_service_down(pool_names=[pool])[0]
    result = result.split("SERVICE_DOWN_ACTION_")[-1].lower()
    return result

def set_action_on_service_down(api, pool, action):
    action = "SERVICE_DOWN_ACTION_%s" % action.strip().upper()
    api.LocalLB.Pool.set_action_on_service_down(pool_names=[pool], actions=[action])

def member_exists(api, pool, address, port):
    # hack to determine if member exists
    result = False
    try:
        members = [{'address': address, 'port': port}]
        api.LocalLB.Pool.get_member_object_status(pool_names=[pool],
                                                  members=[members])
        result = True
    except bigsuds.OperationFailed, e:
        if "was not found" in str(e):
            result = False
        else:
            # genuine exception
            raise
    return result

def delete_node_address(api, address):
    result = False
    try:
        api.LocalLB.NodeAddressV2.delete_node_address(nodes=[address])
        result = True
    except bigsuds.OperationFailed, e:
        if "is referenced by a member of pool" in str(e):
            result = False
        else:
            # genuine exception
            raise
    return result

def remove_pool_member(api, pool, address, port):
    members = [{'address': address, 'port': port}]
    api.LocalLB.Pool.remove_member_v2(pool_names=[pool], members=[members])

def add_pool_member(api, pool, address, port):
    members = [{'address': address, 'port': port}]
    api.LocalLB.Pool.add_member_v2(pool_names=[pool], members=[members])

def main():
    argument_spec=f5_argument_spec();
    argument_spec.update(dict(
            name = dict(type='str', required=True),
            certificate = dict(type='str'),
            key = dict(type='str'),
            chain = dict(type='str'),
            parent_profile = dict(type='str')
        )
    )

    module = AnsibleModule(
        argument_spec = argument_spec,
        supports_check_mode=True
    )

    (server,user,password,state,partition,validate_certs) = f5_parse_arguments(module)

    name = module.params['name']
    profile = fq_name(partition,name)
    certificiate = module.params['certificate']
    if certificate:
        certificate = fq_name(partition,certificate)
    key = module.params['key']
    if key:
        key = fq_name(partition,key)
    chain = module.params['chain']
    if chain:
        chain = fq_name(partition,chain)
    parent_profile = module.params['parent_profile']
    
    if not validate_certs:
        disable_ssl_cert_validation()

    # sanity check user supplied values

    try:
        api = bigip_api(server, user, password)
        result = {'changed': False}  # default

        if state == 'absent':
            if profile_exists(api, name, partition):
                # no host/port supplied, must be pool removal
                if not module.check_mode:
                    # hack to handle concurrent runs of module
                    # pool might be gone before we actually remove it
                    try:
                        remove_profile(api, name, parition)
                        result = {'changed': True}
                    except bigsuds.OperationFailed, e:
                        if "was not found" in str(e):
                            result = {'changed': False}
                        else:
                            # genuine exception
                            raise
                else:
                    # check-mode return value
                    result = {'changed': True}

        elif state == 'present':
            update = False
            if not pool_exists(api, pool):
                # pool does not exist -- need to create it
                if not module.check_mode:
                    # a bit of a hack to handle concurrent runs of this module.
                    # even though we've checked the pool doesn't exist,
                    # it may exist by the time we run create_pool().
                    # this catches the exception and does something smart
                    # about it!
                    try:
                        create_pool(api, pool, lb_method)
                        result = {'changed': True}
                    except bigsuds.OperationFailed, e:
                        if "already exists" in str(e):
                            update = True
                        else:
                            # genuine exception
                            raise
                    else:
                        if monitors:
                            set_monitors(api, pool, monitor_type, quorum, monitors)
                        if slow_ramp_time:
                            set_slow_ramp_time(api, pool, slow_ramp_time)
                        if service_down_action:
                            set_action_on_service_down(api, pool, service_down_action)
                        if host and port:
                            add_pool_member(api, pool, address, port)
                else:
                    # check-mode return value
                    result = {'changed': True}
            else:
                # pool exists -- potentially modify attributes
                update = True

            if update:
                if lb_method and lb_method != get_lb_method(api, pool):
                    if not module.check_mode:
                        set_lb_method(api, pool, lb_method)
                    result = {'changed': True}
                if monitors:
                    t_monitor_type, t_quorum, t_monitor_templates = get_monitors(api, pool)
                    if (t_monitor_type != monitor_type) or (t_quorum != quorum) or (set(t_monitor_templates) != set(monitors)):
                        if not module.check_mode:
                            set_monitors(api, pool, monitor_type, quorum, monitors)
                        result = {'changed': True}
                if slow_ramp_time and slow_ramp_time != get_slow_ramp_time(api, pool):
                    if not module.check_mode:
                        set_slow_ramp_time(api, pool, slow_ramp_time)
                    result = {'changed': True}
                if service_down_action and service_down_action != get_action_on_service_down(api, pool):
                    if not module.check_mode:
                        set_action_on_service_down(api, pool, service_down_action)
                    result = {'changed': True}
                if (host and port) and not member_exists(api, pool, address, port):
                    if not module.check_mode:
                        add_pool_member(api, pool, address, port)
                    result = {'changed': True}

    except Exception, e:
        module.fail_json(msg="received exception: %s" % e)

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.f5 import *
main()

