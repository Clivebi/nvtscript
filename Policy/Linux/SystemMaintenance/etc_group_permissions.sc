if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109812" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-15 13:11:10 +0100 (Fri, 15 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Access /etc/group" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "policy_linux_file_permission.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_add_preference( name: "Uid", type: "entry", value: "root", id: 1 );
	script_add_preference( name: "Gid", type: "entry", value: "root", id: 2 );
	script_add_preference( name: "Permissions", type: "entry", value: "644", id: 3 );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 6.1.4 Ensure permissions on /etc/group are configured (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 6.1.4 Ensure permissions on /etc/group are configured (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 16.4 Encrypt or Hash all Authentication Credentials" );
	script_tag( name: "summary", value: "The file '/etc/group' defines the groups to which users belong.
If wrong access rights for '/etc/groups' are set, users or attackers could gain elevated rights and
illegally access files.
This script checks if the given access rights are set on '/etc/group'." );
	exit( 0 );
}
require("policy_functions.inc.sc");
cmd = "stat /etc/group";
title = "Permissions on /etc/group";
solution = "Run the following command to set permissions on /etc/group:
# chown root:root /etc/group
# chmod 644 /etc/group";
test_type = "SSH_Cmd";
default_uid = script_get_preference( name: "Uid", id: 1 );
default_gid = script_get_preference( name: "Gid", id: 2 );
default_perm = script_get_preference( name: "Permissions", id: 3 );
default = "Uid:" + default_uid + ";Gid:" + default_gid + ";Permissions:" + default_perm;
if( get_kb_item( "policy/linux/access_permissions/error" ) ){
	value = "Error";
	compliant = "incomplete";
	comment = "Could not read /etc/group";
}
else {
	uid = get_kb_item( "Policy/linux//etc/group/user" );
	gid = get_kb_item( "Policy/linux//etc/group/group" );
	perm = get_kb_item( "Policy/linux//etc/group/perm" );
	if( !uid || !gid || !perm ){
		value = "Error";
		compliant = "incomplete";
		comment = "Can not get access permissions on file";
	}
	else {
		if( ( default_uid != uid && default_uid != "Ignore_Preference" ) || ( default_gid != gid && default_gid != "Ignore_Preference" ) || ( policy_access_permissions_match_or_stricter( value: perm, set_point: default_perm ) != "yes" && default_perm != "Ignore_Preference" ) ){
			compliant = "no";
		}
		else {
			compliant = "yes";
		}
	}
	value = "Uid:" + uid + ";Gid:" + gid + ";Permissions:" + perm;
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

