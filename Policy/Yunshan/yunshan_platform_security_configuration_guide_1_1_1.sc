if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150608" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 18:21:30 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Configuring Secure User Authentication Modes and Permission Levels" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Configure user rights in the user-interface VTY view. In
password authentication mode, this permission is the actual login permission. In AAA authentication
mode, this parameter takes effect if no user rights are configured on the AAA server. Configuring
password authentication on the VTY is insecure. Setting the user privilege level will magnify the
risk." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "display current-configuration configuration user-interface | section include vty";
title = "Configuring Secure User Authentication Modes and Permission Levels";
solution = "1. The authentication mode is set to aaa.
2. Delete the user privilege level configuration.";
test_type = "SSH_Cmd";
default = "Run the display current-configuration configuration user-interface command.
If the authentication-mode password or user privilege level command is displayed in the
user-interface VTY view, an error occurs.";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Command did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "-----More----" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
		}
		else {
			if( IsMatchRegexp( value, "authentication-mode\\s+password" ) ){
				compliant = "no";
			}
			else {
				if( IsMatchRegexp( value, "user\\s+privilege\\s+level" ) ){
					compliant = "no";
				}
				else {
					compliant = "yes";
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

