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

# install dependencies
yum install -y sssd authconfig

# write to foxpass_ssh_keys.sh
cat > /usr/local/bin/foxpass_ssh_keys.sh <<"EOF"
#!/bin/sh

user="$1"
eval home_dir="~${user}"
secret="__API_KEY__"
hostname=$(uname -n)

curl -q -f "https://www.foxpass.com/sshkeys/?secret=${secret}&user=${user}&hostname=${hostname}" 2>/dev/null

exit $?
EOF

# swap in the API key
sed -i "s/__API_KEY__/${API_KEY}/" /usr/local/bin/foxpass_ssh_keys.sh

# make it executable
chmod +x /usr/local/bin/foxpass_ssh_keys.sh

authconfig --enablesssd --enablesssdauth --enablelocauthorize --enableldap --enableldapauth --ldapserver=ldaps://ldap.foxpass.com --disableldaptls --ldapbasedn=$BASE_DN --enablemkhomedir --enablecachecreds --update

sed -i "s|TLS_CACERTDIR .*|TLS_CACERT /etc/ssl/certs/ca-bundle.crt|" /etc/openldap/ldap.conf

cat << EOF | python
from SSSDConfig import SSSDConfig

sssdconfig = SSSDConfig()
sssdconfig.import_config('/etc/sssd/sssd.conf')

domain = sssdconfig.get_domain('default')
domain.add_provider('ldap', 'id')
domain.set_option('ldap_tls_reqcert', 'demand')
domain.set_option('ldap_tls_cacert', '/etc/ssl/certs/ca-bundle.crt')
domain.set_option('ldap_default_bind_dn', '$BIND_DN')
domain.set_option('ldap_default_authtok', '$BIND_PW')
domain.set_option('enumerate', True)
domain.remove_option('ldap_tls_cacertdir')

domain.set_active(True)

sssdconfig.save_domain(domain)
sssdconfig.write()
EOF


# add to bottom of sshd_config if it's not already set
if ! grep -q "^AuthorizedKeysCommand" /etc/ssh/sshd_config; then
  cat >> /etc/ssh/sshd_config <<EOF
AuthorizedKeysCommand		/usr/local/bin/foxpass_ssh_keys.sh
AuthorizedKeysCommandUser	nobody
EOF
fi

# restart ssh and sssd
service sshd restart
service sssd restart
