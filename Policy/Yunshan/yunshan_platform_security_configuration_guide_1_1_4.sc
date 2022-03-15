if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150611" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-04-21 18:21:30 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: Check whether the command line permission is proper" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "Sets the execution permission of a specified command. If you
degrade the permission of a high-privilege command, unauthorized operations may occur." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "display current-configuration configuration | inc command-privilege level";
title = "Check whether the command line permission is proper";
solution = "Check whether commands are properly downgraded one by one and delete improper configurations.";
test_type = "SSH_Cmd";
default = "Run the display current-configuration configuration | inc command-privilege level command
to query the command-privilege level.
Expected result: If the command output is configured, an alarm is displayed. If the command output
is not configured, no alarm is generated.";
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
			if( IsMatchRegexp( value, "^Info\\s*:" ) ){
				compliant = "no";
			}
			else {
				compliant = "yes";
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

