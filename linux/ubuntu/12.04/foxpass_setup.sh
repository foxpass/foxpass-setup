#!/bin/sh

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

BASE_DN=$1
BIND_DN="cn=$2,$1"
BIND_PW=$3
API_KEY=$4

add-apt-repository -y ppa:natecarlson/precisebackports
apt-get update

# install dependencies, without the fancy ui
DEBIAN_FRONTEND=noninteractive apt-get install -y curl libnss-ldapd nscd nslcd
DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server

# write to foxpass_ssh_keys.sh
cat > /usr/local/bin/foxpass_ssh_keys.sh <<"EOF"
#!/bin/sh

user="$1"
secret="__API_KEY__"
hostname=`hostname`
if grep -q "^${user}:" /etc/passwd; then exit 1; fi

curl -q -m 5 -f "https://api.foxpass.com/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}" 2>/dev/null

exit $?
EOF

# swap in the API key
sed -i "s/__API_KEY__/${API_KEY}/" /usr/local/bin/foxpass_ssh_keys.sh

# give permissions only to root to protect the API key inside
chmod 700 /usr/local/bin/foxpass_ssh_keys.sh

# write nslcd.conf, with substutions

cat > /etc/nslcd.conf <<EOF
# /etc/nslcd.conf
# nslcd configuration file. See nslcd.conf(5)
# for details.

# The user and group nslcd should run as.
uid nslcd
gid nslcd

# The location at which the LDAP server(s) should be reachable.
uri ldaps://ldap.foxpass.com/

# The search base that will be used for all queries.
base $BASE_DN

# The LDAP protocol version to use.
#ldap_version 3

# The DN to bind with for normal lookups.
binddn $BIND_DN
bindpw $BIND_PW

# The DN used for password modifications by root.
#rootpwmoddn cn=admin,dc=example,dc=com

# SSL options
ssl on
tls_reqcert demand
tls_cacertfile /etc/ssl/certs/ca-certificates.crt

# The search scope.
#scope sub

# don't use LDAP for any users defined in /etc/passwd
nss_initgroups_ignoreusers ALLLOCAL
EOF

# add to bottom of sshd_config if it's not already set
if ! grep -q AuthorizedKeysCommand /etc/ssh/sshd_config; then
  cat >> /etc/ssh/sshd_config <<EOF
AuthorizedKeysCommand		/usr/local/bin/foxpass_ssh_keys.sh
AuthorizedKeysCommandUser	root
EOF
fi

# add to bottom of /etc/pam.d/common-session
if ! grep -q pam_mkhomedir.so /etc/pam.d/common-session; then
  echo "session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel" >> /etc/pam.d/common-session
fi

# add to bottom of /etc/pam.d/common-session-noninteractive
if ! grep -q pam_mkhomedir.so /etc/pam.d/common-session-noninteractive; then
  echo "session required                        pam_mkhomedir.so umask=0022 skel=/etc/skel" >> /etc/pam.d/common-session-noninteractive
fi

# fix up nsswitch
sed -i 's/passwd:.*/passwd:         compat ldap/' /etc/nsswitch.conf
sed -i 's/group:.*/group:          compat ldap/' /etc/nsswitch.conf
sed -i 's/shadow:.*/shadow:         compat ldap/' /etc/nsswitch.conf

# give "sudo" group sudo permissions without password
sed -i 's/^%sudo\tALL=(ALL:ALL) ALL/%sudo ALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers

# restart nslcd, nscd, ssh
service nslcd restart
service nscd restart
service ssh restart
