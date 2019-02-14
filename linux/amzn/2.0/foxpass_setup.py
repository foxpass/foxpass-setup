#!/usr/bin/python

# Copyright (c) 2016-present, Foxpass, Inc.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
from datetime import datetime
import os
import re
import sys
import time
import urllib3


def main():
    parser = argparse.ArgumentParser(description='Set up Foxpass on a linux host.')
    parser.add_argument('--base-dn', required=True, help='Base DN')
    parser.add_argument('--bind-user', required=True, help='Bind User')
    parser.add_argument('--bind-pw', required=True, help='Bind Password')
    parser.add_argument('--api-key', required=True, help='API Key')
    parser.add_argument('--ldap-uri', '--ldap', default='ldaps://ldap.foxpass.com', help='LDAP Server')
    parser.add_argument('--secondary-ldap', dest='ldaps', default=[], action='append', help='Secondary LDAP Server(s)')
    parser.add_argument('--api-url', '--api', default='https://api.foxpass.com', help='API Url')
    parser.add_argument('--secondary-api', dest='apis', default=[], action='append', help='Secondary API Server(s)')
    parser.add_argument('--sudoers-group', default='foxpass-sudo', type=str, help='sudoers group with root access')
    parser.add_argument('--update-sudoers', default=False, action='store_true', help='update 95-foxpass-sudo with new group')
    parser.add_argument('--keep-command', default=False, action='store_true', help='Do not replace sshd key command')
    parser.add_argument('--require-sudoers-pw',
                        default=False,
                        action='store_true',
                        help='set sudoers default password requirement')

    args = parser.parse_args()

    bind_dn = 'cn=%s,%s' % (args.bind_user, args.base_dn)
    apis = [args.api_url] + args.apis

    install_dependencies()
    write_foxpass_ssh_keys_script(apis, args.api_key)
    run_authconfig(args.ldap_uri, args.base_dn)
    configure_sssd(bind_dn, args.bind_pw, args.ldaps)
    augment_sshd_config(args.keep_command)
    fix_sudo(args.sudoers_group, args.require_sudoers_pw, args.update_sudoers)

    # sleep to the next second to make sure sssd.conf has a new timestamp
    time.sleep(1)
    # touch the sssd conf file again
    os.system('touch /etc/sssd/sssd.conf')

    restart()


def install_dependencies():
    # install dependencies
    os.system('yum install -y sssd authconfig')


def write_foxpass_ssh_keys_script(apis, api_key):
    base_curl = 'curl -s -q -m 5 -f -H "Authorization: Token ${secret}" "%s/sshkeys/?user=${user}&hostname=${hostname}'
    curls = []
    for api in apis:
        curls.append(base_curl % api)

    with open('/usr/local/sbin/foxpass_ssh_keys.sh', "w") as w:
        if is_ec2_host():
            append = '&aws_instance_id=${aws_instance_id}&aws_region_id=${aws_region_id}" 2>/dev/null'
            curls = [curl + append for curl in curls]
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`
if grep -q "^${user}:" /etc/passwd; then exit; fi
aws_instance_id=`curl -s -q -f http://169.254.169.254/latest/meta-data/instance-id`
aws_region_id=`curl -s -q -f http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//'`
%s
exit $?
"""
        else:
            append = '" 2>/dev/null'
            curls = [curl + append for curl in curls]
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`
if grep -q "^${user}:" /etc/passwd; then exit; fi
%s
exit $?
"""
        w.write(contents % (api_key, ' || '.join(curls)))

        # give permissions only to root to protect the API key inside
        os.system('chmod 700 /usr/local/sbin/foxpass_ssh_keys.sh')


def run_authconfig(uri, base_dn):
    cmd = 'authconfig --enablesssd --enablesssdauth --enablelocauthorize --enableldap --enableldapauth --ldapserver={uri} --disableldaptls --ldapbasedn={base_dn} --enablemkhomedir --enablecachecreds --update'.format(uri=uri, base_dn=base_dn)
    print 'Running %s' % cmd
    os.system(cmd)


def configure_sssd(bind_dn, bind_pw, backup_ldaps):
    from SSSDConfig import SSSDConfig

    sssdconfig = SSSDConfig()
    sssdconfig.import_config('/etc/sssd/sssd.conf')

    domain = sssdconfig.get_domain('default')
    domain.add_provider('ldap', 'id')
    if backup_ldaps:
        domain.set_option('ldap_backup_uri', ','.join(backup_ldaps))
    domain.set_option('ldap_tls_reqcert', 'demand')
    domain.set_option('ldap_tls_cacert', '/etc/ssl/certs/ca-bundle.crt')
    domain.set_option('ldap_default_bind_dn', bind_dn)
    domain.set_option('ldap_default_authtok', bind_pw)
    domain.set_option('enumerate', True)
    domain.remove_option('ldap_tls_cacertdir')

    domain.set_active(True)

    sssdconfig.save_domain(domain)
    sssdconfig.write()


def augment_sshd_config(keep_command):
    sshd_config_file = '/etc/ssh/sshd_config'
    key_command = 'AuthorizedKeysCommand\t\t/usr/local/sbin/foxpass_ssh_keys.sh\n'
    key_command_user = 'AuthorizedKeysCommandUser\troot\n'
    if not file_contains(sshd_config_file, r'^AuthorizedKeysCommand\w'):
        write_authorizedkeyscommand(sshd_config_file, key_command, key_command_user)
    elif not keep_command:
        if not file_contains(sshd_config_file, r'{}'.format(key_command)):
            clean_authorizedkeyscommand(sshd_config_file)
            write_authorizedkeyscommand(sshd_config_file, key_command, key_command_user)
    else:
        print 'AuthorizedKeysCommand already set, will not use Foxpass for ssh key verification'
        return


def write_authorizedkeyscommand(sshd_config_file, key_command, key_command_user):
    with open(sshd_config_file, 'a') as w:
        w.write('\n')
        w.write(key_command)
        w.write(key_command_user)


def clean_authorizedkeyscommand(sshd_config_file):
    sshd_config_temp_file = '/tmp/sshd_config'
    sshd_config = open(sshd_config_file, 'r')
    lines = sshd_config.readlines()
    sshd_config.close()
    sshd_config_temp = open(sshd_config_temp_file, 'w')
    for line in lines:
        if ('AuthorizedKeysCommand' or 'AuthorizedKeysCommandUser') not in line:
            sshd_config_temp.write(line)
    sshd_config_temp.close()
    os.rename(sshd_config_temp_file, sshd_config_file)


# give "wheel" and chosen sudoers groups sudo permissions without password
def fix_sudo(sudoers, require_sudoers_pw, update_sudoers):
    if not file_contains('/etc/sudoers', r'^#includedir /etc/sudoers.d'):
        with open('/etc/sudoers', 'a') as w:
            w.write('\n#includedir /etc/sudoers.d\n')
    if not os.path.exists('/etc/sudoers.d'):
        os.system('mkdir /etc/sudoers.d && chmod 750 /etc/sudoers.d')
    if not os.path.exists('/etc/sudoers.d/95-foxpass-sudo') or update_sudoers:
        with open('/etc/sudoers.d/95-foxpass-sudo', 'w') as w:
            w.write('# Adding Foxpass group to sudoers\n%{sudo} ALL=(ALL:ALL) {command}'.
                    format(sudo=sudoers, command='ALL' if require_sudoers_pw else 'NOPASSWD:ALL'))
    if not require_sudoers_pw:
        os.system("sed -i 's/^# %wheel\tALL=(ALL)\tNOPASSWD: ALL/%wheel\tALL=(ALL)\tNOPASSWD:ALL/' /etc/sudoers")


def restart():
    os.system("service sssd restart")
    os.system("service sshd restart")


def file_contains(filename, pattern):
    with open(filename) as f:
        for line in f:
            if re.search(pattern, line):
                return True
    return False


def is_ec2_host():
    http = urllib3.PoolManager(timeout=.1)
    url = 'http://169.254.169.254/latest/meta-data/instance-id'
    try:
        r = http.request('GET', url)
        return True
    except Exception:
        return False


if __name__ == '__main__':
    main()
