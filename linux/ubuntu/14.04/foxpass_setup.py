#!/usr/bin/python

# Copyright (c) 2015-present, Foxpass, Inc.
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

# USAGE: sudo ./foxpass_setup.sh dc=example,dc=com <binder_name> <binder_pw> <api_key>
#  e.g.: sudo ./foxpass_setup.sh dc=foxpass,dc=com linux <password> <long_api_key_here>

import argparse
from datetime import datetime
import os
import sys
import urllib3

def main():
    parser = argparse.ArgumentParser(description='Set up Foxpass on a linux host.')
    parser.add_argument('--base-dn', required=True, help='Base DN')
    parser.add_argument('--bind-user', required=True, help='Bind User')
    parser.add_argument('--bind-pw', required=True, help='Bind Password')
    parser.add_argument('--api-key', required=True, help='API Key')
    parser.add_argument('--ldap-uri', default='ldaps://ldap.foxpass.com', help='LDAP Server')
    parser.add_argument('--api-url', default='https://api.foxpass.com')

    args = parser.parse_args()
    print(args)

    binddn = 'cn=%s,%s' % (args.bind_user, args.base_dn)

    now=datetime.now()
    apt_cache_age=datetime.fromtimestamp(os.stat('/var/lib/apt/periodic/update-success-stamp').st_mtime)
    delta = now-apt_cache_age

    if delta.days > 7:
        os.system('apt-get update')

    # install dependencies, without the fancy ui
    os.system('DEBIAN_FRONTEND=noninteractive apt-get install -y curl libnss-ldapd nscd nslcd')

    write_foxpass_ssh_keys_script(args.api_url, args.api_key)
    write_nslcd_conf(uri=args.ldap_uri, basedn=args.base_dn, binddn=binddn, bindpw=args.bind_pw)
    augment_sshd_config()
    augment_pam()
    fix_nsswitch()
    fix_sudo()
    restart()


def write_foxpass_ssh_keys_script(api_url, api_key):
    with open('/usr/local/bin/foxpass_ssh_keys.sh', "w") as w:
        if is_ec2_host():
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`
aws_instance_id=`curl -s -q -f http://169.254.169.254/latest/meta-data/instance-id`
curl -s -q -f "%s/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}&aws_instance_id=${aws_instance_id}" 2>/dev/null

exit $?
"""
        else:
            contents = """\
#!/bin/sh

user="$1"
secret="%s"
hostname=`hostname`

curl -s -q -f "%s/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}" 2>/dev/null

exit $?
"""
        w.write(contents % (api_key, api_url))

        # give permissions only to root to protect the API key inside
        os.system('chmod 700 /usr/local/bin/foxpass_ssh_keys.sh')


# write nslcd.conf, with substutions
def write_nslcd_conf(uri, basedn, binddn, bindpw):
    with open('/etc/nslcd.conf', "w") as w:
        content = """\
# /etc/nslcd.conf
# nslcd configuration file. See nslcd.conf(5)
# for details.

# The user and group nslcd should run as.
uid nslcd
gid nslcd

# The location at which the LDAP server(s) should be reachable.
uri {uri}

# The search base that will be used for all queries.
base {basedn}

# The LDAP protocol version to use.
#ldap_version 3

# The DN to bind with for normal lookups.
binddn {binddn}
bindpw {bindpw}

# The DN used for password modifications by root.
#rootpwmoddn cn=admin,dc=example,dc=com

# SSL options
ssl {sslstatus}
tls_reqcert demand
tls_cacertfile /etc/ssl/certs/ca-certificates.crt

# The search scope.
#scope sub

# don't use LDAP for any users defined in /etc/passwd
nss_initgroups_ignoreusers ALLLOCAL
"""
        sslstatus='off'
        if uri.startswith('ldaps://'):
            sslstatus='on'
        w.write(content.format(uri=uri, basedn=basedn, binddn=binddn, bindpw=bindpw, sslstatus=sslstatus))


def augment_sshd_config():
    if not file_contains('/etc/ssh/sshd_config', 'AuthorizedKeysCommand'):
        with open('/etc/ssh/sshd_config', "a") as w:
            w.write("\n")
            w.write("AuthorizedKeysCommand\t\t/usr/local/bin/foxpass_ssh_keys.sh\n")
            w.write("AuthorizedKeysCommandUser\troot\n")


def augment_pam():
    if not file_contains('/etc/pam.d/common-session', 'pam_mkhomedir.so'):
         with open('/etc/pam.d/common-session', "a") as w:
             w.write('session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel\n')

    if not file_contains('/etc/pam.d/common-session-noninteractive', 'pam_mkhomedir.so'):
         with open('/etc/pam.d/common-session-noninteractive', "a") as w:
             w.write('session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel\n')



def fix_nsswitch():
    os.system("sed -i 's/passwd:.*/passwd:         compat ldap/' /etc/nsswitch.conf")
    os.system("sed -i 's/group:.*/group:          compat ldap/' /etc/nsswitch.conf")
    os.system("sed -i 's/shadow:.*/shadow:         compat ldap/' /etc/nsswitch.conf")

# give "sudo" group sudo permissions without password
def fix_sudo():
    os.system("sed -i 's/^%sudo\tALL=(ALL:ALL) ALL/%sudo ALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers")

def restart():
    # restart nslcd, nscd, ssh
    os.system("service nslcd restart")
    os.system("service nscd restart")
    os.system("service ssh restart")

def file_contains(filename, content):
    with open(filename) as r:
        return content in r.read()

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
