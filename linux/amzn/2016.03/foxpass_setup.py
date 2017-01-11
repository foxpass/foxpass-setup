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
import sys
import time
import urllib3

def main():
    parser = argparse.ArgumentParser(description='Set up Foxpass on a linux host.')
    parser.add_argument('--base-dn', required=True, help='Base DN')
    parser.add_argument('--bind-user', required=True, help='Bind User')
    parser.add_argument('--bind-pw', required=True, help='Bind Password')
    parser.add_argument('--api-key', required=True, help='API Key')
    parser.add_argument('--ldap-uri', default='ldaps://ldap.foxpass.com', help='LDAP Server')
    parser.add_argument('--api-url', default='https://api.foxpass.com', help='API Url')
    parser.add_argument('--ldap-connections', default=2, help='Number of connections to make to LDAP server.')

    args = parser.parse_args()

    bind_dn = 'cn=%s,%s' % (args.bind_user, args.base_dn)

    install_dependencies()
    write_foxpass_ssh_keys_script(args.api_url, args.api_key)
    run_authconfig(args.ldap_uri, args.base_dn)
    configure_sssd(bind_dn, args.bind_pw)
    augment_sshd_config()
    fix_sudo()

    # sleep to the next second to make sure sssd.conf has a new timestamp
    time.sleep(1)
    # touch the sssd conf file again
    os.system('touch /etc/sssd/sssd.conf')

    restart()


def install_dependencies():
    # install dependencies
    os.system('yum install -y sssd authconfig')


def write_foxpass_ssh_keys_script(api_url, api_key):
    with open('/usr/local/bin/foxpass_ssh_keys.sh', "w") as w:
        if is_ec2_host():
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`
if grep -q "^${user}:" /etc/passwd; then exit 1; fi
aws_instance_id=`curl -s -q -f http://169.254.169.254/latest/meta-data/instance-id`
curl -s -q -m 5 -f "%s/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}&aws_instance_id=${aws_instance_id}" 2>/dev/null

exit $?
"""
        else:
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`
if grep -q "^${user}:" /etc/passwd; then exit 1; fi

curl -s -q -m 5 -f "%s/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}" 2>/dev/null

exit $?
"""
        w.write(contents % (api_key, api_url))

        # give permissions only to root to protect the API key inside
        os.system('chmod 700 /usr/local/bin/foxpass_ssh_keys.sh')


def run_authconfig(uri, base_dn):
    cmd = 'authconfig --enablesssd --enablesssdauth --enablelocauthorize --enableldap --enableldapauth --ldapserver={uri} --disableldaptls --ldapbasedn={base_dn} --enablemkhomedir --enablecachecreds --update'.format(uri=uri, base_dn=base_dn)
    print 'Running %s' % cmd
    os.system(cmd)


def configure_sssd(bind_dn, bind_pw):
    from SSSDConfig import SSSDConfig

    sssdconfig = SSSDConfig()
    sssdconfig.import_config('/etc/sssd/sssd.conf')

    domain = sssdconfig.get_domain('default')
    domain.add_provider('ldap', 'id')
    domain.set_option('ldap_tls_reqcert', 'demand')
    domain.set_option('ldap_tls_cacert', '/etc/ssl/certs/ca-bundle.crt')
    domain.set_option('ldap_default_bind_dn', bind_dn)
    domain.set_option('ldap_default_authtok', bind_pw)
    domain.set_option('enumerate', True)
    domain.remove_option('ldap_tls_cacertdir')

    domain.set_active(True)

    sssdconfig.save_domain(domain)
    sssdconfig.write()


def augment_sshd_config():
    if not file_contains('/etc/ssh/sshd_config', '^AuthorizedKeysCommand'):
        with open('/etc/ssh/sshd_config', "a") as w:
            w.write("\n")
            w.write("AuthorizedKeysCommand\t\t/usr/local/bin/foxpass_ssh_keys.sh\n")
            w.write("AuthorizedKeysCommandUser\troot\n")


# give "wheel" group sudo permissions without password
def fix_sudo():
    os.system("sed -i 's/^# %wheel\tALL=(ALL)\tNOPASSWD: ALL/%wheel\tALL=(ALL)\tNOPASSWD:ALL/' /etc/sudoers")

def restart():
    os.system("service sssd restart")
    os.system("service sshd restart")

def file_contains(filename, regex):
    import re
    pat = re.compile(regex)
    with open(filename) as f:
        for line in f:
            if pat.search(line):
                return True

    return False


def is_ec2_host():
    http = urllib3.PoolManager(timeout=.1)
    url = 'http://169.254.169.254/latest/meta-data/instance-id'
    try:
        r = http.request('GET', url)
        return True
    except:
        return False

if __name__ == '__main__':
    main()
