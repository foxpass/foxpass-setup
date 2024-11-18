#!/usr/bin/python3

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

import argparse
from datetime import datetime
import difflib
import os
import re
import sys
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
    parser.add_argument('--ldap-connections', default=2, type=int, help='Number of connections to make to LDAP server.')
    parser.add_argument('--idle-timelimit', default=600, type=int, help='LDAP idle time out setting, default to 10m')
    parser.add_argument('--sudoers-group', default='foxpass-sudo', type=str, help='sudoers group with root access')
    parser.add_argument('--update-sudoers', default=False, action='store_true', help='update 95-foxpass-sudo with new group')
    parser.add_argument('--require-sudoers-pw', default=False, action='store_true', help='set sudoers default password requirement')
    parser.add_argument('--debug', default=False, action='store_true', help='Turn on debug mode')
    # Foxpass SUDOers add-on
    parser.add_argument('--enable-ldap-sudoers', default=False, action='store_true', help='Enable Foxpass SUDOers')
    parser.add_argument('--sudoers-timed', default=False, action='store_true', help='Toggle sudoers_timed parameter')
    parser.add_argument('--bind-timelimit', default=30, help='The amount of time, in seconds, to wait while trying to connect to an LDAP server.')
    parser.add_argument('--query-timelimit', default=30, help='The amount of time, in seconds, to wait while performing an LDAP query.')

    args = parser.parse_args()

    binddn = 'cn=%s,%s' % (args.bind_user, args.base_dn)
    apis = [args.api_url] + args.apis
    uris = [args.ldap_uri] + args.ldaps

    if args.debug:
        foxpass_ssh_keys_path = '/usr/local/sbin/foxpass_ssh_keys.sh'
        nslcd_path = '/etc/nslcd.conf'
        sshd_config_path = '/etc/ssh/sshd_config'
        cs_path = '/etc/pam.d/common-session'
        csn_path = '/etc/pam.d/common-session-noninteractive'
        nsswitch_path = '/etc/nsswitch.conf'
        sudoers_path = '/etc/sudoers'
        foxpass_sudo_path = '/etc/sudoers.d/95-foxpass-sudo'
        sudo_ldap_path = '/etc/sudo-ldap.conf'

        from_file_foxpass_ssh_keys = open_file(foxpass_ssh_keys_path)
        from_file_nslcd = open_file(nslcd_path)
        from_file_sshd_config = open_file(sshd_config_path)
        from_file_cs = open_file(cs_path)
        from_file_csn = open_file(csn_path)
        from_file_nsswitch = open_file(nsswitch_path)
        from_sudoers_file = open_file(sudoers_path)
        from_foxpass_sudo_file = open_file(foxpass_sudo_path)
        from_file_sudo_ldap = open_file(sudo_ldap_path)

    apt_get_update()
    install_dependencies()
    write_foxpass_ssh_keys_script(apis, args.api_key)
    write_nslcd_conf(uris, args.base_dn, binddn, args.bind_pw, args.ldap_connections, args.idle_timelimit)
    augment_sshd_config()
    augment_pam()
    fix_nsswitch()
    fix_sudo(args.sudoers_group, args.require_sudoers_pw, args.update_sudoers)
    fix_eic()

    if args.enable_ldap_sudoers:
        write_ldap_sudoers(uris, args.base_dn, binddn, args.bind_pw, args.sudoers_timed, args.bind_timelimit, args.query_timelimit)

    if args.debug:
        to_file_foxpass_ssh_keys = open_file(foxpass_ssh_keys_path)
        to_file_nslcd = open_file(nslcd_path)
        to_file_sshd_config = open_file(sshd_config_path)
        to_file_cs = open_file(cs_path)
        to_file_csn = open_file(csn_path)
        to_file_nsswitch = open_file(nsswitch_path)
        to_sudoers_file = open_file(sudoers_path)
        to_foxpass_sudo_file = open_file(foxpass_sudo_path)
        to_file_sudo_ldap = open_file(sudo_ldap_path)

        diff_files(from_file_foxpass_ssh_keys, to_file_foxpass_ssh_keys, foxpass_ssh_keys_path)
        diff_files(from_file_nslcd, to_file_nslcd, nslcd_path)
        diff_files(from_file_sshd_config, to_file_sshd_config, sshd_config_path)
        diff_files(from_file_cs, to_file_cs, cs_path)
        diff_files(from_file_csn, to_file_csn, csn_path)
        diff_files(from_file_nsswitch, to_file_nsswitch, nsswitch_path)
        diff_files(from_sudoers_file, to_sudoers_file, sudoers_path)
        diff_files(from_foxpass_sudo_file, to_foxpass_sudo_file, foxpass_sudo_path)
        diff_files(from_file_sudo_ldap, to_file_sudo_ldap, sudo_ldap_path)

    restart()


def apt_get_update():
    # This section requires that the update-notifier package be installed.
    update_notifier_file = '/var/lib/apt/periodic/update-success-stamp'
    notifier_file_exists = os.path.exists(update_notifier_file)

    if not notifier_file_exists:
        # No way to check last apt-get update, so we always run.
        os.system('apt-get update')
    else:
        # Otherwise only if it hasn't been updated in over 7 days.
        now = datetime.now()
        apt_cache_age = datetime.fromtimestamp(os.stat(update_notifier_file).st_mtime)
        delta = now - apt_cache_age
        if delta.days > 7:
            os.system('apt-get update')


def install_dependencies():
    # install dependencies, without the fancy ui
    # capture the return code and exit passing the code if apt-get fails
    return_code = os.system('DEBIAN_FRONTEND=noninteractive apt-get install -y curl libnss-ldapd nscd nslcd')
    if return_code != 0:
        # bitshift right 8 to get rid of the signal portion of the return code
        sys.exit(return_code >> 8)


def write_foxpass_ssh_keys_script(apis, api_key):
    base_curl = 'curl -q --disable --silent --fail --max-time 5 --header "Authorization: Token ${secret}" "%s/sshkeys/?user=${user}&hostname=${hostname}'
    curls = []
    for api in apis:
        curls.append(base_curl % api)

    with open('/usr/local/sbin/foxpass_ssh_keys.sh', "w") as w:
        if is_ec2_host():
            append = '&aws_instance_id=${aws_instance_id}&aws_region_id=${aws_region_id}" 2>/dev/null'
            curls = [curl + append for curl in curls]
            contents = r"""#!/bin/bash

user="$1"
secret="%s"
pwfile="/etc/passwd"
hostname=$(hostname)
if grep -q "^${user/./\\.}:" $pwfile; then echo "User $user found in file $pwfile, exiting." > /dev/stderr; exit; fi
common_curl_args="--disable --silent --fail"
aws_token=`curl -m 10 $common_curl_args -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 30"`
if [ -z "$aws_token" ]
then
  aws_instance_id=`curl $common_curl_args http://169.254.169.254/latest/meta-data/instance-id`
  aws_region_id=`curl $common_curl_args http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//'`
else
  aws_instance_id=`curl $common_curl_args -H "X-aws-ec2-metadata-token: ${aws_token}" http://169.254.169.254/latest/meta-data/instance-id`
  aws_region_id=`curl $common_curl_args -H "X-aws-ec2-metadata-token: ${aws_token}" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed 's/.$//'`
fi

%s
exit $?
"""
        elif is_gce_host():
            append = '&provider=gce&gce_instance_id=${gce_instance_id}&gce_zone=${gce_zone}&gce_project_id=${gce_project_id}${gce_networks}${gce_network_tags}" 2>/dev/null'
            curls = [curl + append for curl in curls]
            contents = r"""#!/bin/bash

user="$1"
secret="%s"
pwfile="/etc/passwd"
hostname=$(hostname)
headers="Metadata-Flavor: Google"
if grep -q "^${user/./\\.}:" $pwfile; then echo "User $user found in file $pwfile, exiting." > /dev/stderr; exit; fi
common_curl_args="--disable --silent --fail"
gce_instance_id=`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/instance/id`
gce_zone=`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/instance/zone`
gce_project_id=`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/project/project-id`
networks=(`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/`)
gce_networks=''
for gce_network in "${networks[@]}"
do
    gce_network=`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/${gce_network}network`
    gce_networks="${gce_networks}&gce_networks[]=${gce_network}"
done
network_tags=(`curl $common_curl_args -H "${headers}" http://metadata.google.internal/computeMetadata/v1/instance/tags?alt=text`)
gce_network_tags=''
for gce_network_tag in "${network_tags[@]}"
do
    gce_network_tags="${gce_network_tags}&gce_network_tags[]=${gce_network_tag}"
done

%s
exit $?
"""
        else:
            append = '" 2>/dev/null'
            curls = [curl + append for curl in curls]
            contents = r"""#!/bin/bash

user="$1"
secret="%s"
pwfile="/etc/passwd"
hostname=$(hostname)
if grep -q "^${user/./\\.}:" $pwfile; then echo "User $user found in file $pwfile, exiting." > /dev/stderr; exit; fi
%s
exit $?
"""
        w.write(contents % (api_key, ' || '.join(curls)))

        # give permissions only to root to protect the API key inside
        os.system('chmod 700 /usr/local/sbin/foxpass_ssh_keys.sh')


# write nslcd.conf, with substutions
def write_nslcd_conf(uris, basedn, binddn, bindpw, threads, idle_timelimit):
    with open('/etc/nslcd.conf', "w") as w:
        content = """\
# /etc/nslcd.conf
# nslcd configuration file. See nslcd.conf(5)
# for details.

# number of threads. one LDAP connction per thread.
threads {threads}

# Set how long to keep ldap connections to foxpass open.
# By default Foxpass sets this to 600s.
idle_timelimit {idle_timelimit}

# The user and group nslcd should run as.
uid nslcd
gid nslcd

# The location at which the LDAP server(s) should be reachable.
uri {uris}

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
        sslstatus = 'off'
        if uris[0].startswith('ldaps://'):
            sslstatus = 'on'
        w.write(content.format(uris='\nuri '.join(uris), basedn=basedn, binddn=binddn,
                               bindpw=bindpw, sslstatus=sslstatus, threads=threads, idle_timelimit=idle_timelimit))


def augment_sshd_config():
    if not file_contains('/etc/ssh/sshd_config', r'^AuthorizedKeysCommand\w'):
        with open('/etc/ssh/sshd_config', "a") as w:
            w.write("\n")
            w.write("AuthorizedKeysCommand\t\t/usr/local/sbin/foxpass_ssh_keys.sh\n")
            w.write("AuthorizedKeysCommandUser\troot\n")


def augment_pam():
    if not file_contains('/etc/pam.d/common-session', r'pam_mkhomedir\.so'):
        with open('/etc/pam.d/common-session', "a") as w:
            w.write('session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel\n')

    if not file_contains('/etc/pam.d/common-session-noninteractive', r'pam_mkhomedir\.so'):
        with open('/etc/pam.d/common-session-noninteractive', "a") as w:
            w.write('session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel\n')


def fix_nsswitch():
    os.system("sed -i 's/passwd:.*/passwd:         compat ldap/' /etc/nsswitch.conf")
    os.system("sed -i 's/group:.*/group:          compat ldap/' /etc/nsswitch.conf")
    os.system("sed -i 's/shadow:.*/shadow:         compat ldap/' /etc/nsswitch.conf")

def write_ldap_sudoers(uris, basedn, binddn, bindpw, sudoers_timed, bind_timelimit, query_timelimit):
    check_sudo_passwd()
    return_code = os.system('DEBIAN_FRONTEND=noninteractive apt-get install -y sudo-ldap')
    if return_code != 0:
        # bitshift right 8 to get rid of the signal portion of the return code
        sys.exit(return_code >> 8)
    with open('/etc/sudo-ldap.conf', "w") as w:
        content = """\
#
# LDAP Defaults
#

# See ldap.conf(5) for details
# This file should be world readable but not world writable.

URI         {uri}
BINDDN      {binddn}
BINDPW      {bindpw}

# The amount of time, in seconds, to wait while trying to connect to
# an LDAP server.
bind_timelimit {bind_timelimit}
#
# The amount of time, in seconds, to wait while performing an LDAP query.
timelimit {query_timelimit}
#
# Must be set or sudo will ignore LDAP; may be specified multiple times.
sudoers_base   ou=SUDOers,{basedn}
#
# verbose sudoers matching from ldap
sudoers_debug 0
#
# Enable support for time-based entries in sudoers.
sudoers_timed {sudoers_timed}

#SIZELIMIT      12
#TIMELIMIT      15
#DEREF          never

# TLS certificates (needed for GnuTLS)
TLS_CACERT      /etc/ssl/certs/ca-certificates.crt
"""
        w.write(content.format(uri=uris[0], basedn=basedn, binddn=binddn, bindpw=bindpw,
            sudoers_timed=str(sudoers_timed).lower(), bind_timelimit=bind_timelimit, query_timelimit=query_timelimit))


# give "sudo" and chosen sudoers groups sudo permissions without password
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
        os.system("sed -i 's/^%sudo\tALL=(ALL:ALL) ALL/%sudo ALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers")


# Amazon is hard loading their configs if they don't dectect everything,
# this will ignore some future changes made to /etc/ssh/config files.
# We move it to disabled, to revert simply rename the file without the .disabled
def fix_eic():
    eic_file = '/lib/systemd/system/ssh.service.d/ec2-instance-connect.conf'
    if os.path.exists(eic_file):
        os.system('systemctl stop ssh.service')
        os.system('mv {} {}.disabled'.format(eic_file, eic_file))
        os.system('systemctl daemon-reload')


def check_sudo_passwd():
    result = os.popen('passwd --status root').read().split(' ')
    if result and result[1] != 'P':
        sys.exit('Please set the password of the `root` user before enabling ldap sudoers. E.g sudo passwd root')


def restart():
    # restart nslcd, nscd, ssh
    os.system('systemctl restart nslcd.service')
    os.system('systemctl restart nscd.service')
    os.system('systemctl restart ssh.service')


def file_contains(filename, pattern):
    with open(filename) as f:
        for line in f:
            if re.search(pattern, line):
                return True
    return False


def is_gce_host():
    http = urllib3.PoolManager(timeout=.1)
    url = 'http://metadata.google.internal/computeMetadata/v1/instance/'
    try:
        r = http.request('GET', url, headers={"Metadata-Flavor": "Google"})
        if r.status != 200:
            raise Exception
        return True
    except Exception:
            return False


def is_ec2_host():
    http = urllib3.PoolManager(timeout=.1)
    url = 'http://169.254.169.254/latest/api/token'
    try:
        r = http.request('PUT', url, headers={"X-aws-ec2-metadata-token-ttl-seconds": 30})
        if r.status != 200:
            raise Exception
        return True
    except Exception:
        return is_ec2_host_imds_v1_fallback()


def is_ec2_host_imds_v1_fallback():
    http = urllib3.PoolManager(timeout=.1)
    url = 'http://169.254.169.254/latest/meta-data/instance-id'
    try:
        r = http.request('GET', url)
        # Check the response if it is returning the right instance id.
        # The medatada endpoint works on VMWare vm but it's not the value we are expecting.
        pattern="^i-[a-f0-9]{8}(?:[a-f0-9]{9})?$"
        if re.match(pattern, r.data.decode('utf-8')):
            return True
        else:
            raise Exception
    except Exception:
        return False


def open_file(path):
    if os.path.exists(path):
        with open(path, 'r') as file:
            return file.readlines()
    else:
        return []


def diff_files(from_file, to_file, filename):
    diff = difflib.unified_diff(from_file, to_file, fromfile='Old {}'.format(filename), tofile='New {}'.format(filename))
    for line in diff:
        sys.stdout.write(line)


if __name__ == '__main__':
    main()
