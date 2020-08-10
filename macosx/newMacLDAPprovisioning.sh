#!/bin/sh

# Determine OS version
osvers=$(sw_vers -productVersion | awk -F. '{print $2}')

# Environment settings
LDAPdomain="ldap.foxpass.com" 		# Fully qualified DNS of new LDAP server

# do env-var check for bind credential set
if [ -z $BINDUSER ] || [ -z $BINDPW ]; then
   echo Please set env var \$BINDUSER and \$BINDPW
   exit 1;
fi 


if dscl localhost -list /LDAPv3 | grep . > /dev/null; then
    check4OD=$(dscl localhost -list /LDAPv3 | awk 'NR<2{print $NF}')
    echo "Found LDAP: "$check4OD
else
    echo "No LDAP binding found"
fi

# Check if bound to the old LDAP server
# and remove the old LDAP server settings
 
if [[ "${check4OD}" == "${oldLDAPdomain}" ]]; then
    /bin/echo "This machine is joined to ${oldLDAPdomain}"
    /bin/echo "Removing from ${oldLDAPdomain}"
        dsconfigldap -r "${oldLDAPdomain}"
        /usr/bin/dscl localhost -delete Search CSPSearchPath /LDAPv3/"${oldLDAPdomain}"
        /usr/bin/dscl localhost -delete Contact CSPSearchPath /LDAPv3/"${oldLDAPdomain}"
fi


echo "Binding to LDAP Domain "$LDAPdomain

if [[ ${osvers} -lt 7 ]]; then
   if [[ ! -d '/Library/Preferences/DirectoryService' ]]; then
    	echo "mkdir /Library/Preferences/DirectoryService"
   fi

   if [[ -f /Library/Preferences/DirectoryService/DSLDAPv3PlugInConfig.plist ]]; then
     echo "rm /Library/Preferences/DirectoryService/DSLDAPv3PlugInConfig.plist"
   fi
fi



  if [[ -f /Library/Preferences/DirectoryService/DSLDAPv3PlugInConfig.plist ]]; then
     rm /Library/Preferences/DirectoryService/DSLDAPv3PlugInConfig.plist
     mv /tmp/$LDAPdomain.plist /Library/Preferences/DirectoryService/DSLDAPv3PlugInConfig.plist
  fi


  echo "Killing DirectoryService"
  killall DirectoryService
  
  echo "Giving Directory Services some time to reload..."
  sleep 10

  
  echo "Killing DirectoryService"
  killall DirectoryService

if [[ ${osvers} -ge 7 ]]; then
	if [[ ! -d /Library/Preferences/OpenDirectory/Configurations/LDAPv3 ]]; then
    	mkdir /Library/Preferences/OpenDirectory/Configurations/LDAPv3
	fi

	if [[ -f /Library/Preferences/OpenDirectory/Configurations/LDAPv3/$LDAPdomain.plist ]]; then
    	mv /Library/Preferences/OpenDirectory/Configurations/LDAPv3/$LDAPdomain.plist /tmp/config_$LDAPdomain.plist
	fi
fi

if [[ ${osvers} -ge 7 ]]; then
/bin/cat > /tmp/$LDAPdomain.plist << NEW_LDAP_BIND
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>description</key>
	<string>Foxpass onprem</string>
	<key>mappings</key>
	<dict>
		<key>attributes</key>
		<array>
			<string>objectClass</string>
		</array>
		<key>function</key>
		<string>ldap:translate_recordtype</string>
		<key>recordtypes</key>
		<dict>
			<key>dsRecTypeStandard:Users</key>
			<dict>
				<key>attributetypes</key>
				<dict>
					<key>dsAttrTypeStandard:GeneratedUID</key>
					<dict>
						<key>native</key>
						<string>entryUUID</string>
					</dict>
					<key>dsAttrTypeStandard:NFSHomeDirectory</key>
					<dict>
						<key>native</key>
						<string>#/Users/$uid$</string>
					</dict>
					<key>dsAttrTypeStandard:PrimaryGroupID</key>
					<dict>
						<key>native</key>
						<string>#20</string>
					</dict>
					<key>dsAttrTypeStandard:RealName</key>
					<dict>
						<key>native</key>
						<string>cn</string>
					</dict>
					<key>dsAttrTypeStandard:RecordName</key>
					<dict>
						<key>native</key>
						<string>uid</string>
					</dict>
					<key>dsAttrTypeStandard:UniqueID</key>
					<dict>
						<key>native</key>
						<string>uidNumber</string>
					</dict>
					<key>dsAttrTypeStandard:UserShell</key>
					<dict>
						<key>native</key>
						<string>#/bin/bash</string>
					</dict>
				</dict>
				<key>info</key>
				<dict>
					<key>Group Object Classes</key>
					<string>OR</string>
					<key>Object Classes</key>
					<array>
						<string>posixAccount</string>
					</array>
					<key>Search Base</key>
					<string>ou=people,dc=example,dc=com</string>
				</dict>
			</dict>
		</dict>
		<key>template</key>
		<string>LDAPv3</string>
	</dict>
	<key>module options</key>
	<dict>
		<key>AppleODClient</key>
		<dict>
			<key>Server Mappings</key>
			<false/>
		</dict>
		<key>ldap</key>
		<dict>
			<key>Denied SASL Methods</key>
			<array>
				<string>DIGEST-MD5</string>
			</array>
		</dict>
	</dict>
	<key>node name</key>
	<string>/LDAPv3/$LDAPdomain</string>
	<key>options</key>
	<dict>
		<key>connection idle disconnect</key>
		<integer>120</integer>
		<key>destination</key>
		<dict>
			<key>host</key>
			<string>$LDAPdomain</string>
			<key>other</key>
			<string>ldaps</string>
			<key>port</key>
			<integer>636</integer>
		</dict>
		<key>man-in-the-middle</key>
		<false/>
		<key>no cleartext authentication</key>
		<false/>
		<key>packet encryption</key>
		<integer>3</integer>
		<key>packet signing</key>
		<integer>1</integer>
	</dict>
	<key>template</key>
	<string>LDAPv3</string>
	<key>trustaccount</key>
	<string>cn=$BINDUSER,dc=example,dc=com</string>
	<key>trustoptions</key>
	<array>
		<string>system keychain</string>
	</array>
	<key>trusttype</key>
	<string>authenticated</string>
	<key>uuid</key>
	<string>DAFDA6E4-3F97-415E-B77F-1BDE504F7C0F</string>
</dict>
</plist>

NEW_LDAP_BIND

    if [[ ! -f /Library/Preferences/OpenDirectory/Configurations/LDAPv3/$LDAPdomain.plist ]]; then
    	mv /tmp/$LDAPdomain.plist /Library/Preferences/OpenDirectory/Configurations/LDAPv3/$LDAPdomain.plist
    fi
    
    sleep 5

	echo "Killing opendirectoryd"
	killall opendirectoryd

fi

echo "Finished OD Binding."
# Give DS a chance to catch up
sleep 5

echo "Add search path"
dscl localhost -merge Search CSPSearchPath /LDAPv3/$LDAPdomain

echo "remove bind user entry"
sudo security delete-generic-password -a cn=$BINDUSER,dc=foxpass,dc=com
echo "set bind credential"
sudo security add-generic-password -a cn=$BINDUSER,dc=foxpass,dc=com -A -s /LDAPv3/$LDAPdomain -w $BINDPW -U /Library/Keychains/System.keychain

#echo "manual step next: make sure you are on wired network...  - add local search dir. - update bind pw. "
#echo "press enter when done"
#read pause;

