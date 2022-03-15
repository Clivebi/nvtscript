if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.109820" );
	script_version( "2021-05-18T12:49:08+0000" );
	script_tag( name: "last_modification", value: "2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)" );
	script_tag( name: "creation_date", value: "2019-03-18 11:05:45 +0100 (Mon, 18 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Ungrouped files or directories" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linuxhandbook.com/linux-file-permissions/" );
	script_xref( name: "Policy", value: "CIS Distribution Independent Linux v2.0.0: 6.1.12 Ensure no ungrouped files or directories exist (Scored)" );
	script_xref( name: "Policy", value: "CIS CentOS Linux 8 Benchmark v1.0.0: 6.1.12 Ensure no ungrouped files or directories exist (Scored)" );
	script_xref( name: "Policy", value: "CIS Controls Version 7: 13.2 Remove Sensitive Data or Systems Not Regularly Accessed by Organization" );
	script_tag( name: "summary", value: "If a user or group is deleted from the system but files or
directories are not, new users with these UID or GID own these files, leading to potentially having
more access than intended.

This script checks if any ungrouped file or directory exists on the host." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
cmd = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup";
title = "Ungrouped files or directories";
solution = "Locate files that are owned by users or groups not listed in the system configuration files,
and reset the ownership of these files to some active user on the system as appropriate.";
test_type = "SSH_Cmd";
default = "None";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	value = "Error";
	compliant = "incomplete";
	comment = "No SSH connection";
}
else {
	value = ssh_cmd( cmd: cmd, socket: sock, nosh: TRUE, return_errors: TRUE );
	if( value ){
		compliant = "no";
	}
	else {
		value = "None";
		compliant = "yes";
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

